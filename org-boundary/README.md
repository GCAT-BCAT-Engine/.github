# GCAT-BCAT-Engine Organizational Boundary

`GCAT-BCAT-Engine/.github` is the canonical specification and bootstrap home for the GCAT-BCAT-Engine organizational ingress/egress boundary.

HB or HB-derived carrier -> governed InTr envelope -> organizational ingress -> normalization/provenance -> service resolution -> internal dispatch -> endpoint consumption -> result/evidence binding -> organizational egress -> governed InTr envelope -> carrier.

HB and HB-derived carriers provide synchronization/carrier capability only. They grant no admission, execution, credential, routing, transition, receiving, publication, custody, or release authority. The boundary may validate, normalize, resolve, route, and bind evidence; applicable transition elements determine authority effects.

Source presence, validation, merge, deployment, activation, ingress observation, dispatch, consumption, result binding, egress observation, same-execution reconstruction, and release remain distinct states.

See `registry/services.json` for internal endpoints.
