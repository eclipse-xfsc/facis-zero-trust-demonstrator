// Stage the release's real assets before triggering this installer.
// Read every required file before emitting writes to avoid partial installs.
const sourceRoot = env.get('FACIS_UI_SOURCE_DIR') || '/data/facis-demo-release/ui/demonstrator/src';
const destinationRoot = '/data/uibuilder/facis-demo/src';
const names = [
  'index.html',
  'index.css',
  'index.js',
  'vendor/vue.global.js',
  'vendor/LICENSE.vue',
  'assets/Facis-logo.svg',
  'assets/favicon-32x32.png',
  'assets/favicon-192x192.png',
  'assets/apple-touch-icon-180x180.png'
];

let files;
try {
  if (!sourceRoot.startsWith('/') || sourceRoot.replace(/\/$/, '') === destinationRoot) {
    throw new Error('Stage release assets in a separate absolute source directory.');
  }
  files = names.map(name => {
    const payload = nodeFS.readFileSync(sourceRoot.replace(/\/$/, '') + '/' + name);
    if (!payload.length || payload.length > 2 * 1024 * 1024) {
      throw new Error('Required UI asset is empty or exceeds the size limit: ' + name);
    }
    return { filename: destinationRoot + '/' + name, payload };
  });
} catch (error) {
  node.status({ fill: 'red', shape: 'ring', text: 'UI source assets unavailable' });
  node.error(error.message, msg);
  return null;
}

const installId = Date.now().toString(36);
for (const file of files) {
  node.send({ ...file, installId, installFiles: files.length });
}
return null;
