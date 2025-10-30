package terraform

# Tamaños permitidos
allowed_sizes := {"M10", "M20", "M30", "M40", "M50"}

# Acciones permitidas
allowed_actions := {"create", "update"}

# Deny si algún cluster tiene size no permitido
deny[msg] {
    some r
    resource := input.resource_changes[r]

    # Solo clusters de MongoDB Atlas
    resource.type == "mongodbatlas_cluster"

    # Verifica que alguna acción sea permitida
    some i
    allowed_actions[resource.change.actions[i]]

    # Extrae el size
    size := resource.change.after.provider_instance_size_name
    size != null

    # Si el size no está permitido → deny
    not allowed_sizes[size]

    # Mensaje
    msg := sprintf(
        "El recurso %s tiene un provider_instance_size_name no permitido: %s",
        [resource.address, size]
    )
}
