# Casbin SQL Adaper

This is an sql-adapter for Casbin. With this library, Casbin can load policy from PostgresSQL/Mysql or save policy to it.

### Installation
`go get github.com/inagornyi/casbin-sql-adapter`

### Usage
```go
a, err := NewAdapter("mysql", "root", "root", "127.0.0.1:3306", "casbin", "casbin_rule")
if err != nil {
    panic(err)
}
e, err := casbin.NewEnforcer("model.conf", a)
```