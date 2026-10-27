# Catalog addition (G17: a new check is a catalog group, never a new workflow file): the
# companion committed-request binding, the source-ledger pairing (GCAT#15) and the B-P40
# trigger rule. Ledger roots are runner-temporary; nothing is pushed.
python -m unittest tests.test_committed_request_binding tests.test_workflow_triggers -v
