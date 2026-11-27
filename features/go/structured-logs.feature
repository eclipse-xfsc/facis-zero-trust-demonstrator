@platform @regression
Feature: Service logs are structured JSON
  A regression check behind Annex A row TDR-BDD-06, which it does not prove. TDR-BDD-06 is the
  scenario in orce-qa.feature: a controlled error in ORCE, its JSON log and its error object in
  the ORCE context, on a cluster. The scenario below covers the Go services the row's "relevant
  runtime logs" also name: each service binary is started with a configuration it rejects, and
  every line it writes before it stops must be one JSON object naming a level and a message.
  A wrong command or flag prints the usage text of a command-line tool and is not a log.

  Scenario: A service that rejects its configuration reports it as structured JSON
    Given the service binaries of the demonstrator
    When each service is started with a configuration it rejects
    Then every line each service writes is a JSON log record
