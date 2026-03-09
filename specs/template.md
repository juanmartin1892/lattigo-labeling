# [Nombre de la Feature]

**ID:** NNN  
**Estado:** Draft | Ready | In Progress | Done  
**Fecha:** YYYY-MM-DD  
**Autor:** juanmartin

---

## Objetivo

[Qué problema resuelve esta feature, en 2-3 líneas]

---

## Contexto

[Por qué es necesaria. Relación con otras features. Referencias a papers si aplica]

---

## Interfaz Pública

```go
// Firma(s) de funciones/tipos públicos que se van a crear/modificar
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `ejemplo(input1)` | `output1` |
| `ejemplo(input2)` | `output2` |

---

## Casos Edge

- [ ] Caso edge 1 (ej: parámetros cero)
- [ ] Caso edge 2 (ej: overflow)
- [ ] Caso edge 3 (ej: nil pointer)

---

## Dependencias

- Spec #XXX (si depende de otra)
- Paquetes externos nuevos (si los hay)

---

## Criterios de Aceptación

- [ ] Tests table-driven escritos y pasando
- [ ] Función implementada según interfaz pública
- [ ] GoDoc completo en inglés
- [ ] go vet sin warnings
- [ ] go test -race sin data races
- [ ] go build ./... exitoso
- [ ] Casos edge cubiertos

---

## Notas de Implementación (opcional)

[Detalles de implementación, decisiones de diseño, complejidad algorítmica]
