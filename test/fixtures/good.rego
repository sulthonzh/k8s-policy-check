# Enforce container resource limits
package k8s.policies.resources

# Check that all containers have resource limits
violation[msg] {
    container := input.review.object.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container <%v> has no resource limits", [container.name])
}
