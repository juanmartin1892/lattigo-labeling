# /review

Agent: plan

Descripcion: revisa una implementacion contra su spec.

Uso:
```
/review NNN
```

Workflow:
1) Leer `specs/features/NNN-*.md`.
2) Identificar archivos asociados por cambios recientes.
3) Revisar:
   - Compliance con la spec.
   - Calidad de codigo segun AGENTS.md.
   - Calidad de tests.
   - Criptografia (si aplica).
4) Reportar problemas por severidad:
   - Bloqueante
   - Importante
   - Menor

Reglas:
- No modificar codigo.
- Usar `$ARGUMENTS` como entrada.
