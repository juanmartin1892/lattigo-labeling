Implementa una spec siguiendo TDD estricto.

Argumentos: `$ARGUMENTS` (ID de la spec, ej. `001`)

Workflow (orden estricto):
1. Leer `specs/features/$ARGUMENTS-*.md`.
2. Verificar estado `Ready`. Si es ambiguo, PARAR y preguntar.
3. Crear rama de trabajo:
   - `git checkout -b feature/$ARGUMENTS-nombre-descriptivo`
4. Escribir tests table-driven con `t.Run` y cubrir casos edge.
5. Ejecutar tests y confirmar que FALLAN.
6. Implementar el codigo minimo para pasar los tests.
7. Ejecutar validaciones:
   - `go build ./...`
   - `go vet ./...`
   - `go test -race ./...`
8. Marcar criterios de aceptacion completados en la spec y cambiar a `Done`.
9. Commits atomicos:
   - `git add <tests>`
   - `git commit -m "test($ARGUMENTS): add tests for <feature>"`
   - `git add <implementacion>`
   - `git commit -m "feat($ARGUMENTS): implement <feature>"`
10. Push y PR:
    - `git push -u origin feature/$ARGUMENTS-nombre-descriptivo`
    - `gh pr create --title "feat($ARGUMENTS): descripcion corta" --body <checklist criterios>`
11. Mostrar resumen final.

Reglas:
- NUNCA implementar sin tests que fallen primero.
- NUNCA saltar el orden.
- Si la spec no es clara, detenerse y pedir aclaracion.
