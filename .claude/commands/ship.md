Publica el codigo actual en GitHub creando una rama y un Pull Request a main.

Argumentos: `$ARGUMENTS` (tipo y descripcion, ej. `feature "add rotation overflow"` o `fix "correct label index"`)

Workflow (orden estricto):
1. Parsear argumentos: tipo = primera palabra (`feature` o `fix`), descripcion = resto entre comillas o sin ellas. Si faltan o el tipo es invalido, PARAR y mostrar uso correcto.
2. Ejecutar `git status` y `git branch --show-current` para conocer el estado y la rama actual.
3. Gestionar la rama de trabajo:
   - Si la rama actual es `main`: sanitizar descripcion a kebab-case (minusculas, espacios y caracteres especiales → guiones) y crear rama con `git checkout -b <tipo>/<descripcion-kebab>`.
   - Si ya esta en rama `feature/` o `fix/`: continuar en ella sin crear una nueva.
   - Si esta en cualquier otra rama: PARAR con mensaje explicativo e instrucciones.
4. Ejecutar `git status --short` para verificar que hay cambios. Si el arbol de trabajo esta limpio y no hay nada staged, PARAR indicandolo.
5. Revisar datos sensibles — ejecutar `git diff HEAD` sobre los ficheros modificados y buscar:
   - Patrones: `(password|passwd|secret|token|api.?key|private.?key|auth.?key|credential)\s*[:=]\s*\S+` (case-insensitive)
   - Claves PEM o SSH: lineas que contengan `-----BEGIN`
   - Cadenas hexadecimales de 40+ caracteres que parezcan hashes o tokens
   - Valores hardcodeados en variables de entorno dentro del codigo fuente
   Si se detecta alguno:
   a. Mostrar exactamente que se detecto, fichero y linea.
   b. Reemplazar el valor sensible en el fichero fuente por `<REDACTED>` o extraerlo a una variable de entorno documentada.
   c. Si la anonimizacion automatica no es segura, PARAR y pedir al usuario que lo corrija manualmente antes de continuar.
   Si no se detecta nada sensible, continuar.
6. Verificar que no se van a incluir ficheros prohibidos: `.env`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, archivos binarios grandes. Si alguno esta staged o modificado, excluirlo del staging y avisar al usuario.
7. Ejecutar validaciones si hay ficheros `.go` modificados:
   - `go build ./...`
   - `go vet ./...`
   - `go test -race ./...`
   Si alguna validacion falla, PARAR, mostrar el error y no continuar hasta que el codigo este limpio.
8. Hacer staging selectivo y commit:
   - `git add <ficheros de codigo relevantes>` (excluir los prohibidos del paso 6)
   - Tipo `feature` → `git commit -m "feat: <descripcion>"`
   - Tipo `fix` → `git commit -m "fix: <descripcion>"`
9. Push: `git push -u origin <rama>`
10. Crear PR con `gh pr create` usando HEREDOC:
    - Titulo: `feat: <descripcion>` o `fix: <descripcion>`
    - Body: seccion de resumen con que cambia y por que, seguido de checklist de validaciones:
      - [ ] `go build ./...` pasa sin errores
      - [ ] `go vet ./...` pasa sin advertencias
      - [ ] `go test -race ./...` pasa sin fallos
      - [ ] No se incluyen datos sensibles ni credenciales
      - [ ] Los cambios son coherentes con la descripcion del PR
    - No incluir referencias a herramientas de IA ni textos de autoria automatica.
11. Mostrar la URL del PR creado.

Reglas:
- NUNCA hacer push directamente a `main`.
- NUNCA saltarse la revision de datos sensibles (paso 5).
- NUNCA saltarse las validaciones de Go si hay ficheros `.go` modificados (paso 7).
- NUNCA incluir ficheros `.env`, `*.key`, `*.pem` u otros ficheros de credenciales en el commit.
- NUNCA subir valores sensibles detectados en el diff; anonimizarlos antes o parar.
- Si el tipo no es `feature` ni `fix`, PARAR con el mensaje: "Uso: /ship <feature|fix> \"descripcion\""
