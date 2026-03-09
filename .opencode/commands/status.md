# /status

Agent: plan

Descripcion: genera un resumen de todas las specs en `specs/features/`.

Uso:
```
/status
```

Workflow:
1) Leer todas las specs en `specs/features/*.md`.
2) Extraer: ID, nombre, estado, criterios completados vs total, archivos asociados.
3) Generar tabla ordenada por ID.
4) Resumen final:
   - Totales por estado.
   - Proxima spec en estado Ready.
   - Specs Draft que requieren revision.

Reglas:
- Solo lectura.
- No modificar archivos.
