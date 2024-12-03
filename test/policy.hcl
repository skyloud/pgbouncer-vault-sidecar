path "database/creds/my-role" {
    capabilities = ["read", "list"]
}

path "auth/token/lookup-self" {
    capabilities = ["read"]
}
