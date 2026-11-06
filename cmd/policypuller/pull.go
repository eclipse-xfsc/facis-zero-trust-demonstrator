package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// ArtifactType is the artefact type policy-publish.sh pushes; a manifest of any other type at the
// channel tag is not a policy package, whoever signed it.
const ArtifactType = "application/vnd.facis.ztd.policy.v1"

// createdAnnotation orders the packages: the workflow sets it to the commit's time, and the signature
// covers the manifest it is in. A package older than the followed one is a rollback, not a release.
const createdAnnotation = "org.opencontainers.image.created"

// The puller's record on the Application: the last digest it verified and wrote, that package's
// created time (what a candidate is ordered against), when it wrote it, and the last refusal, which
// a success clears. Events carry the same for an hour; the annotations stay.
const (
	AnnotationDigest   = "facis.ztd/policy-digest"
	AnnotationCreated  = "facis.ztd/policy-created"
	AnnotationVerified = "facis.ztd/policy-verified"
	AnnotationRefused  = "facis.ztd/policy-refused"
)

// Event reasons.
const (
	ReasonApplied     = "PolicyPackageApplied"
	ReasonRefused     = "PolicyPackageRefused"
	ReasonUnavailable = "PolicyPackageUnavailable"
)

// Refusal: the package at the tag must not be applied. Nothing was changed.
type Refusal struct{ Reason, Detail string }

func (r *Refusal) Error() string { return r.Reason + ": " + r.Detail }

// Unavailable: the registry or the API server could not be consulted. Nothing was changed, and
// nothing is known about the package.
type Unavailable struct {
	Detail string
	Err    error
}

func (u *Unavailable) Error() string { return u.Detail + ": " + u.Err.Error() }
func (u *Unavailable) Unwrap() error { return u.Err }

// Outcome of a pull that did not fail.
type Outcome struct {
	Digest, Created string
	// Changed: the Application was patched with this digest; false when it already followed it.
	Changed bool
}

// Puller holds one run's configuration.
type Puller struct {
	Registry, Repository, Tag string
	Keys                      []*ecdsa.PublicKey
	Namespace, Application    string
	Client                    *ociclient.Client
	Kube                      *kubeClient
	Now                       func() time.Time
}

type manifest struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
}

// Pull resolves the tag, verifies the package and writes its digest to the Application when it is
// new and newer. A refusal and an unavailability are recorded on the Application (an Event, and the
// refused annotation) before they are returned, so a failed run is visible without its log.
func (p *Puller) Pull(ctx context.Context) (Outcome, error) {
	app, out, err := p.pull(ctx)
	var refused *Refusal
	var unavailable *Unavailable
	switch {
	case errors.As(err, &refused):
		p.record(ctx, app, "Warning", ReasonRefused, refused.Error())
	case errors.As(err, &unavailable):
		p.record(ctx, app, "Warning", ReasonUnavailable, unavailable.Error())
	}
	return out, err
}

// pull returns the Application it read, for record: nil when the API server could not be reached.
func (p *Puller) pull(ctx context.Context) (*application, Outcome, error) {
	// The Application first: what the candidate is ordered against, and where every outcome is recorded.
	app, err := p.Kube.getApplication(ctx, p.Namespace, p.Application)
	if err != nil {
		return nil, Outcome{}, &Unavailable{"application " + p.Namespace + "/" + p.Application, err}
	}
	m, err := p.Client.ManifestByTag(ctx, p.Registry, p.Repository, p.Tag)
	if errors.Is(err, ociclient.ErrNotFound) {
		return app, Outcome{}, &Refusal{"no-package", "nothing is published at tag " + p.Tag}
	}
	if err != nil {
		return app, Outcome{}, &Unavailable{"registry " + p.Registry, err}
	}
	if m.MediaType != ociclient.MediaTypeOCIManifest {
		return app, Outcome{}, &Refusal{"not-a-policy-package", "the tag names a " + m.MediaType + ", not an OCI manifest"}
	}
	var mf manifest
	if err := json.Unmarshal(m.Body, &mf); err != nil {
		return app, Outcome{}, &Refusal{"not-a-policy-package", "manifest: " + err.Error()}
	}
	if mf.ArtifactType != ArtifactType {
		return app, Outcome{}, &Refusal{"not-a-policy-package", fmt.Sprintf("artifact type %q, want %q", mf.ArtifactType, ArtifactType)}
	}
	created, err := time.Parse(time.RFC3339, mf.Annotations[createdAnnotation])
	if err != nil {
		return app, Outcome{}, &Refusal{"unordered", "no usable " + createdAnnotation + " annotation: the package cannot be ordered against the one followed"}
	}

	ref := cosignverify.Ref{Registry: p.Registry, Repository: p.Repository, Digest: m.Digest}
	switch r := cosignverify.VerifySignature(ctx, p.Client, ref, p.Keys); {
	case r.Code == cosignverify.CodeProviderDown:
		return app, Outcome{}, &Unavailable{"registry " + p.Registry, errors.New(r.Detail)}
	case !r.OK():
		return app, Outcome{}, &Refusal{"unsigned", r.Code + ": " + r.Detail}
	}

	// Ordered against the package last verified here, not against the registry: a tag moved back to
	// an older digest is refused even once the newer one is gone from the registry.
	if pinned, err := time.Parse(time.RFC3339, app.Metadata.Annotations[AnnotationCreated]); err == nil && created.Before(pinned) {
		return app, Outcome{}, &Refusal{"rollback", fmt.Sprintf("the package at %s was created %s, before the one followed (%s)",
			p.Tag, created.Format(time.RFC3339), pinned.Format(time.RFC3339))}
	}
	out := Outcome{Digest: m.Digest, Created: created.Format(time.RFC3339)}
	if app.Spec.Source.Helm.ValuesObject.Package.Digest == m.Digest && app.Metadata.Annotations[AnnotationDigest] == m.Digest {
		// Already followed. A refusal recorded since (the tag moved away and back) no longer holds.
		if app.Metadata.Annotations[AnnotationRefused] != "" {
			if err := p.Kube.patchApplication(ctx, p.Namespace, p.Application,
				map[string]any{"metadata": map[string]any{"annotations": map[string]any{AnnotationRefused: nil}}}); err != nil {
				return app, Outcome{}, &Unavailable{"application " + p.Namespace + "/" + p.Application, err}
			}
		}
		return app, out, nil
	}

	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	patch := map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			AnnotationDigest:   m.Digest,
			AnnotationCreated:  out.Created,
			AnnotationVerified: now().UTC().Format(time.RFC3339),
			AnnotationRefused:  nil,
		}},
		"spec": map[string]any{"source": map[string]any{"helm": map[string]any{"valuesObject": map[string]any{
			"package": map[string]any{"digest": m.Digest},
		}}}},
	}
	if err := p.Kube.patchApplication(ctx, p.Namespace, p.Application, patch); err != nil {
		return app, Outcome{}, &Unavailable{"application " + p.Namespace + "/" + p.Application, err}
	}
	out.Changed = true
	p.record(ctx, app, "Normal", ReasonApplied, fmt.Sprintf("%s/%s@%s (created %s) verified and applied", p.Registry, p.Repository, m.Digest, out.Created))
	return app, out, nil
}

// record writes an Event on the Application and, for a warning, the refused annotation when it
// changed. Best effort: what it cannot write is lost with the run's log, never a failure of the run.
// app is the Application as pull read it; nil when pull could not, in which case nothing is tried.
func (p *Puller) record(ctx context.Context, app *application, kind, reason, message string) {
	if app == nil {
		return
	}
	_ = p.Kube.createEvent(ctx, p.Namespace, app, kind, reason, message)
	if kind == "Warning" && app.Metadata.Annotations[AnnotationRefused] != message {
		_ = p.Kube.patchApplication(ctx, p.Namespace, p.Application,
			map[string]any{"metadata": map[string]any{"annotations": map[string]any{AnnotationRefused: message}}})
	}
}
