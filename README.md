# Vulnerability Validation Framework

> **Una solución GenAI utilizando CrewAI para validar vulnerabilidades mediante técnicas de análisis estático y dinámico.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![CrewAI](https://img.shields.io/badge/CrewAI-Latest-green.svg)](https://crewai.com)
[![Semgrep](https://img.shields.io/badge/Semgrep-Latest-yellow.svg)](https://semgrep.dev)

## Características

- **5 Agentes ReAct**: Lector, Estático, Dinámico, Triaje y orquestación
- **Análisis Completo**: PDF parsing, análisis estático con Semgrep, testing dinámico
- **Múltiples LLMs**: Soporte para OpenAI GPT, DeepSeek, xAI Grok, Anthropic Claude y Google Gemini
- **Modos de Ejecución**: Análisis completo o agentes individuales
- **Persistencia**: Almacenamiento en MongoDB
- **CLI/API Ready**: Interfaz de línea de comandos con preparación para API

## Instalación

1. Clonar el repositorio:
```bash
git clone <repository-url>
cd vulnerability-validation
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Configurar variables de entorno:
```bash
# Crear archivo .env (al menos una API key es requerida)
echo "OPENAI_API_KEY=your_openai_api_key" >> .env
echo "DEEPSEEK_API_KEY=your_deepseek_api_key" >> .env
echo "XAI_API_KEY=your_xai_api_key" >> .env
echo "ANTHROPIC_API_KEY=your_anthropic_api_key" >> .env
echo "GEMINI_API_KEY=your_gemini_api_key" >> .env
echo "MONGODB_URI=mongodb://localhost:27017/" >> .env
```

4. Instalar Semgrep:
```bash
pip install semgrep
```

## Uso

### Análisis Completo
```bash
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/
```

### Especificar Modelo LLM
```bash
# OpenAI GPT
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/ --model gpt-4o-mini

# DeepSeek
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/ --model deepseek-chat

# xAI Grok
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/ --model grok-beta

# Anthropic Claude
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/ --model claude-3-5-sonnet-20241022

# Google Gemini
python app.py --pdf report.pdf --source vuln-app/ --url http://localhost/ --model gemini-1.5-pro
```

### Modelos Soportados

#### OpenAI
- `gpt-4o`, `gpt-4o-mini`
- `gpt-4-turbo`, `gpt-4`
- `gpt-3.5-turbo`
- `o1-preview`, `o1-mini`

#### DeepSeek
- `deepseek-chat`
- `deepseek-coder`

#### xAI (Grok)
- `grok-beta`
- `grok-vision-beta`

#### Anthropic Claude
- `claude-3-5-sonnet-20241022`
- `claude-3-5-haiku-20241022`
- `claude-3-opus-20240229`
- `claude-3-sonnet-20240229`
- `claude-3-haiku-20240307`

#### Google Gemini
- `gemini-1.5-pro`
- `gemini-1.5-flash`
- `gemini-1.0-pro`



### Ejecutar Solo un Agente
```bash
# Solo análisis de PDF
python app.py --pdf report.pdf --only-read

# Solo análisis estático
python app.py --source vuln-app/ --only-static

# Solo análisis dinámico
python app.py --url http://localhost/ --only-dynamic
```

### Opciones Disponibles

- `--pdf`: Ruta al archivo PDF del reporte de vulnerabilidades
- `--source`: Directorio del código fuente para análisis estático
- `--url`: URL objetivo para testing dinámico
- `--model`: Modelo LLM a utilizar (default: gpt-4o-mini)
- `--only-read`: Ejecutar solo el agente lector
- `--only-static`: Ejecutar solo el agente de análisis estático
- `--only-dynamic`: Ejecutar solo el agente de testing dinámico
- `--output`: Archivo de salida para guardar resultados (opcional)

## Arquitectura

### Agentes

1. **Reader Agent**: Extrae y estructura información de reportes PDF
2. **Static Agent**: Ejecuta Semgrep y analiza código fuente
3. **Dynamic Agent**: Realiza testing de penetración en vivo
4. **Triage Agent**: Consolida resultados y determina estado final

### Metodología ReAct

Cada agente sigue el patrón Reasoning and Action:
- **REASON**: Analiza el contexto y planifica acciones
- **ACT**: Ejecuta herramientas y recopila información
- **REASON**: Evalúa resultados y determina próximos pasos

### Estados de Vulnerabilidad

- **Vulnerable**: Confirmado por testing dinámico o evidencia estática fuerte
- **Not Vulnerable**: Sin evidencia creíble en ningún análisis
- **Possible**: Solo evidencia estática sin confirmación dinámica (solo para agente estático)

## Configuración

### Variables de Entorno

```bash
# API Keys
OPENAI_API_KEY=your_openai_api_key
DEEPSEEK_API_KEY=your_deepseek_api_key

# Database
MONGODB_URI=mongodb://localhost:27017/

# Logging
LOG_LEVEL=INFO
```

### MongoDB

Los resultados se almacenan en MongoDB con la siguiente estructura:
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "execution_metadata": {
    "pdf_path": "report.pdf",
    "source_path": "vuln-app/",
    "target_url": "http://localhost/",
    "model_used": "gpt-4o-mini",
    "execution_mode": "full"
  },
  "assessment_result": {
    "vulnerabilities": [...],
    "summary": {...}
  }
}
```

## Herramientas Incluidas

### PDF Tools
- Extracción de texto completo
- Metadatos del documento
- Procesamiento por páginas

### File Tools
- Lectura de archivos de código
- Listado recursivo de directorios
- Búsqueda de archivos por patrón

### Network Tools
- Solicitudes HTTP personalizadas
- Escaneo de puertos
- Ejecución de comandos de red
- Web crawling y descubrimiento

## Desarrollo

### Estructura del Proyecto
```
.
├── app.py                 # Punto de entrada CLI
├── requirements.txt       # Dependencias
├── src/
│   ├── crew.py           # Orquestador CrewAI
│   ├── agents/           # Definiciones de agentes
│   ├── tasks/            # Definiciones de tareas
│   ├── tools/            # Herramientas para agentes
│   └── utils/            # Utilidades (DB, config)
└── README.md
```

### Agregar Nuevos Agentes

1. Crear clase de agente en `src/agents/`
2. Implementar metodología ReAct
3. Definir herramientas específicas
4. Agregar tarea correspondiente en `src/tasks/`
5. Integrar en `src/crew.py`

### Agregar Nuevas Herramientas

1. Crear herramienta en `src/tools/`
2. Heredar de `BaseTool` de CrewAI
3. Implementar método `_run()`
4. Agregar a agente correspondiente

## Troubleshooting

### Errores Comunes

1. **API Key no configurada**:
   ```
   Error: No API keys configured
   ```
   Solución: Configurar al menos una de las siguientes API keys:
   - `OPENAI_API_KEY` para modelos OpenAI GPT
   - `DEEPSEEK_API_KEY` para modelos DeepSeek
   - `XAI_API_KEY` para modelos xAI Grok
   - `ANTHROPIC_API_KEY` para modelos Anthropic Claude
   - `GEMINI_API_KEY` para modelos Google Gemini

2. **MongoDB no disponible**:
   ```
   Warning: Database connection failed
   ```
   Solución: Los resultados se guardarán solo en archivo

3. **Semgrep no encontrado**:
   ```
   Error: semgrep command not found
   ```
   Solución: `pip install semgrep`

### Logs

Los logs se guardan en `vulnerability_validation.log` y se muestran en consola.

## Licencia

MIT License

## Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crear rama feature
3. Commit cambios
4. Push a la rama
5. Crear Pull Request