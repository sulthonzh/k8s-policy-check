package k8s.custom.check

allow {
    input.request.kind.kind == "Pod"
}
