"""CloudFormation provider checks — pre-deploy template scanning.

Mirrors the Terraform provider's shape: static analysis over a
declarative AWS-resource document. Where Terraform consumes the JSON
produced by ``terraform show -json`` (all attributes already resolved),
CloudFormation consumes the raw author-source template — so intrinsic
functions (``!Ref``, ``!Sub``, ``!GetAtt``, ...) stay unresolved.

Rules therefore treat intrinsic expressions as *opaque*: a
``EnableLogFileValidation: !Ref EnableValidation`` value is considered
"not provably true" and fails the check. This is stricter than
Terraform (which sees the resolved boolean), but safer for shift-left.
"""
