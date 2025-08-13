# Triage GenIA - Informe y Ejemplos

El objetivo de este proyecto es implementar una solucion GenIA utilizando un framework de agentes que tome como entrada un reporte de vulnerabilidad y valide la existencia de estas vulnerabilidades mediante tecnicas de analisis estatico y dinamico.

## Enfoque

Se utilizo CrewAI para implementar los agentes y coordinar su ejecucion. Se diseñaron 4 agentes:

1. **Agente de Lectura**: Se encarga de leer y analizar el documento PDF proporcionado.
2. **Agente Estático**: Realiza un análisis estático del código fuente para identificar posibles vulnerabilidades.
3. **Agente Dinámico**: Utiliza técnicas de análisis dinámico para detectar vulnerabilidades en tiempo de ejecución.
4. **Agente de Triage**: Se encarga de evaluar los resultados de los agentes anteriores y generar un triage final.

Cada agente tiene una tarea específica y se comunica entre sí para coordinar su ejecución. El Agente de Lectura extrae información relevante del reporte de vulnerabilidad, el Agente Estático realiza un análisis estático del código fuente, el Agente Dinámico realiza un análisis dinámico, y el Agente de Triage evalúa los resultados y genera un triage final.

Se implemento el modelo ReAct para que cada agente decida si continuar con la siguiente tarea o finalizar el proceso.

Los resultados se almacenan en una base de datos NoSQL para su posterior consulta y análisis. Se opto por MongoDB Atlas.

> [!NOTE]
> Una base de datos no relacional es mas adecuada para este proyecto debido a:
> - Escalabilidad
> - Flexibilidad
> - Almacenamiento de datos no estructurados y semi-estructurados
> - Alta disponibilidad y tolerancia a fallos
> - Facilidad de implementación y mantenimiento

## Resultados

En el repositorio se encuentra una aplicacion vulnerable de prueba, la cual se uso para validar el funcionamiento de la solucion. La aplicacion se encuentra en la carpeta `vulnerable-app`.

