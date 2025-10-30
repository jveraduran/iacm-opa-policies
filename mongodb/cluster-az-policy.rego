package terraform

# Regiones permitidas para MongoDB Atlas
allowed_regions := {"US_EAST_1"}

# Acciones permitidas
allowed_actions := {"create", "update"}

# Deny si algún cluster se crea o actualiza en una región no permitida
deny[msg] {
    some r
    resource := input.resource_changes[r]

    # Solo clusters de MongoDB Atlas
    resource.type == "mongodbatlas_cluster"

    # Verifica que haya al menos una acción permitida
    some i
    allowed_actions[resource.change.actions[i]]

    # Extrae la región del cluster
    region := resource.change.after.provider_region_name

    # Ignora valores null
    region != null

    # Si la región no está permitida → deny
    not allowed_regions[region]

    # Mensaje de violación
    msg := sprintf(
        "El recurso %s tiene una provider_region_name no permitida: %s",
        [resource.address, region]
    )
}
