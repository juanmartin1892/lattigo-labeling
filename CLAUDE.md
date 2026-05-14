# CLAUDE.md

## Descripcion del proyecto

Proyecto en Go que implementa tecnicas de labeling sobre el esquema BFV de cifrado homomorfico usando Lattigo. Objetivo: extender profundidad multiplicativa mediante etiquetado de ciphertexts. Licencia Apache 2.0.

## Estado actual del repositorio

- Modulo: `main.go` (go.mod)
- Version Go: 1.25.1
- Paquete principal: `labeling`
- Esquema usado en el codigo: paquete `bgv` de Lattigo v6.1.1 (intencion BFV)
- Tipos clave: `PlaintextLabeledciphertext`, `CiphertextLabeledciphertext`, `Labeledciphertext[T]`
- Ejemplos en `examples/` para sumas, multiplicaciones, rotaciones y overflow

## Specs de features

Las specs de features activas se encuentran en `specs/features/*.md`. Lee los archivos relevantes cuando trabajes en una feature nueva o existente. Usa `specs/template.md` como plantilla para crear nuevas specs.

## Workflow obligatorio (Spec-Driven Development)

- Flujo: spec -> tests -> implementar -> refactor
- NUNCA codigo sin spec
- NUNCA codigo sin tests
- Specs en `specs/features/NNN-*.md` usando `specs/template.md`
- Estado `Ready` antes de implementar
- Tests deben fallar antes de implementar
- Al finalizar, marcar la spec como `Done`

## Convenciones Go

- Codigo idiomatico
- Errors como valores, no `panic`
- Interfaces pequenas definidas donde se consumen
- Nombres descriptivos: `ciphertext`, `plaintext`, `parameters` (evitar `ct`, `pt`, `params`)
- GoDoc en todo exportado, en ingles, estilo descriptivo
- Evitar cambios breaking sin spec

## Convenciones de tests

- Table-driven tests con `t.Run` siempre
- `t.Helper` en funciones auxiliares
- `t.Parallel` solo si es seguro (sin estado compartido)
- Deterministas (semillas fijas cuando aplique)
- Verificar errores explicitamente
- Criptografia: verificar correctitud matematica, no solo ausencia de error

## Convenciones Lattigo

- Usar tipos de Lattigo (`bgv.Parameters`, `rlwe.Ciphertext`, `rlwe.SecretKey`)
- Documentar parametros criptograficos: `LogN`, `LogQ`, `LogP`, `PlaintextModulus`
- Justificar eleccion de parametros (seguridad, slots, profundidad)
- Comentar operaciones homomorficas no triviales con explicacion matematica
- Indicar efectos en ruido para relinearization, rotaciones y key-switching

## Git workflow

- NUNCA hacer commit directo a `main`
- Al iniciar implementacion de spec NNN: `git checkout -b feature/NNN-nombre-descriptivo`
- Naming de ramas: `feature/NNN-nombre` para features, `fix/NNN-nombre` para correcciones
- Commits: conventional commits en ingles (`feat:`, `test:`, `fix:`, `docs:`, `refactor:`)
- Commits atomicos: tests separados de implementacion
- Al terminar, hacer push de la rama y crear PR con `gh pr create`
- Titulo de PR: `feat(NNN): descripcion corta`
- Body de PR: checklist de criterios de aceptacion de la spec
- Prohibido: merge directo, push a `main`, force push a `main`

## Notas de evolucion

<!--
Esta seccion documenta aprendizajes y decisiones del proyecto a medida que evoluciona.
Agregar aqui patrones descubiertos, problemas recurrentes y decisiones de arquitectura.
-->
