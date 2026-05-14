Crea o revisa una especificacion siguiendo `specs/template.md`.

Argumentos: `$ARGUMENTS` (descripcion de feature nueva o ID existente, ej. `001`)

Workflow:
1. Leer `specs/template.md`.
2. Si `$ARGUMENTS` es una descripcion nueva:
   - Detectar el siguiente ID secuencial en `specs/features/` (formato NNN).
   - Crear `specs/features/NNN-nombre-descriptivo.md`.
   - Completar campos basicos con estado `Draft`, fecha actual y autor `juanmartin`.
3. Si `$ARGUMENTS` es un ID existente:
   - Leer la spec indicada.
   - Revisar objetivo, interfaz publica, casos edge y criterios verificables.
   - Sugerir mejoras para pasar a estado `Ready`.

Reglas:
- No implementar codigo.
- No crear tests.
