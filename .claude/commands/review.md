Revisa una implementacion contra su spec.

Argumentos: `$ARGUMENTS` (ID de la spec, ej. `001`)

Workflow:
1. Leer `specs/features/$ARGUMENTS-*.md`.
2. Identificar archivos asociados por cambios recientes (`git diff main..HEAD`).
3. Revisar:
   - Compliance con la spec.
   - Calidad de codigo segun CLAUDE.md.
   - Calidad de tests.
   - Criptografia (si aplica).
4. Reportar problemas por severidad:
   - Bloqueante
   - Importante
   - Menor

Reglas:
- No modificar codigo.
