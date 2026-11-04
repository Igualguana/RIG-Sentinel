# RIG Sentinel (Español)

**Escáner de seguridad open source para agentes de IA, servidores MCP, identidades,
permisos y riesgos de exposición.**

[English README](../README.md) · [Limitaciones](LIMITATIONS.md) · [Seguridad](../SECURITY.md) · [Licencia Apache 2.0](../LICENSE)

---

## ¿Qué es?

RIG Sentinel analiza de forma **estática** un repositorio de código y responde:

1. ¿Qué agentes de IA e integraciones MCP existen?
2. ¿Qué identidades y credenciales referencian?
3. ¿Qué capacidades sensibles pueden alcanzar y por qué rutas?
4. ¿Qué conviene restringir primero para reducir la exposición?

Se ejecuta localmente, **no tiene dependencias de ejecución**, nunca ejecuta el código
analizado y genera reportes en terminal, JSON, HTML offline y SARIF 2.1.0.

> **Importante:** los resultados son **indicadores heurísticos** que requieren revisión,
> no vulnerabilidades explotables confirmadas.

## Capacidades de la versión 0.1.0

- Detección de proveedores de IA: OpenAI, Anthropic, LangChain, CrewAI.
- Detección de agentes candidatos (heurística).
- Detección de servidores y configuraciones MCP (`mcpServers`, `mcp.json`, SDK de MCP en Python).
- Herramientas sensibles: ejecución de shell, escritura/borrado de archivos, HTTP, envío de correo.
- Referencias a credenciales e identidades (solo **nombres**, nunca valores).
- Flujo de credenciales, privilegios excesivos y mínimo privilegio.
- Referencias compartidas a credenciales y agentes no aprobados (*shadow agents*).
- Grafo multiagente, propagación de riesgo, rutas de ataque y *blast radius*.
- Recomendaciones de remediación y políticas **consultivas**.

## Instalación

Requiere Python 3.11 o superior (probado con Python 3.13).

```bash
git clone https://github.com/Igualguana/RIG-Sentinel.git
cd RIG-Sentinel
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1
python -m pip install .
```

Detalles: [INSTALLATION.md](INSTALLATION.md) (en inglés).

## Uso

```bash
rig-sentinel scan <ruta>                      # reporte en terminal
rig-sentinel scan <ruta> --json               # JSON por salida estándar
rig-sentinel scan <ruta> --html reporte.html  # HTML offline
rig-sentinel scan <ruta> --sarif reporte.sarif  # SARIF 2.1.0
```

El código de salida es `0` aunque existan hallazgos; RIG Sentinel no bloquea pipelines
por sí mismo. Referencia completa: [CLI_REFERENCE.md](CLI_REFERENCE.md).

Inventario de agentes aprobados en `.rig-sentinel.toml`:

```toml
approved_agents = ["billing_agent", "support_agent"]
```

## Cómo interpretar los resultados

- **El análisis es estático:** no se ejecuta código ni se observa el comportamiento en runtime.
- **Los agentes detectados son candidatos heurísticos**, no un inventario confirmado.
- **Que varios agentes referencien la misma variable de credencial no demuestra que usen
  el mismo secreto.** Distintos entornos pueden asignar valores diferentes al mismo nombre.
- **Las rutas de ataque son posibilidades modeladas**, no exploits demostrados.
- **El *blast radius* es una estimación** (0–100), no un incidente confirmado ni una
  probabilidad de brecha.
- **Las políticas son consultivas (*advisory*)**; no hay *enforcement* en runtime.
- Se omiten directorios como `tests/`, `examples/`, `fixtures/`, `vendor/` y archivos de más de 1 MB.
- Los resultados SARIF pueden no incluir ubicación de archivo; la carga a GitHub code
  scanning no está verificada en v0.1.0.

Más detalles: [LIMITATIONS.md](LIMITATIONS.md).

## Seguridad

No reporte vulnerabilidades en issues públicos. Use el reporte privado de GitHub descrito
en [SECURITY.md](../SECURITY.md). Los reportes generados contienen rutas y **nombres** de
credenciales: revíselos antes de compartirlos.

## Contribuir

Las contribuciones son bienvenidas y se aceptan bajo la Apache License 2.0 (no se
requiere CLA). Consulte [CONTRIBUTING.md](../CONTRIBUTING.md), el
[Código de Conducta](../CODE_OF_CONDUCT.md) y la guía para reportar falsos positivos y
falsos negativos: [DETECTION_ISSUES.md](DETECTION_ISSUES.md).

## Community y Enterprise

| | **RIG Sentinel Community** | **RIG Sentinel Enterprise** |
|---|---|---|
| Estado | Disponible (este repositorio) | **Producto futuro, no disponible** |
| Licencia | Apache License 2.0 | Comercial (planificada) |
| Precio | Gratuito | No definido; no se ofrece a la venta |
| Alcance | Todas las capacidades actuales listadas arriba | Planificado: dashboard centralizado, multi-organización, monitoreo continuo, controles de permisos en ejecución, políticas empresariales, integraciones corporativas, auditoría centralizada, usuarios y roles, reportes empresariales, soporte y servicios profesionales |

Las funcionalidades de Community no se eliminarán para convertirlas en funciones de pago.
Enterprise, si se construye, será un producto separado que no forma parte de este repositorio.

## Hoja de ruta

| Fase | Estado |
|---|---|
| **Fase 1 — Community Scanner** | Implementada, en preparación de release |
| **Fase 2 — Runtime Permission Security** | Planificada, no implementada |
| **Fase 3 — Enterprise Platform** | Futura |

Detalles: [ROADMAP.md](ROADMAP.md) (en inglés).

## Acerca de RIG Sentinel

RIG Sentinel fue fundado y creado por **Randy Igualguana**, quien es también su
mantenedor principal. RIG Industrial Technologies LLC es la empresa operadora comercial
propuesta para futuros productos y servicios comerciales, incluido el futuro RIG Sentinel
Enterprise.

| | |
|---|---|
| **Fundador, creador y mantenedor principal** | Randy Igualguana — [@Igualguana](https://github.com/Igualguana) |
| **Copyright** | © 2026 Randy Igualguana |
| **Operador comercial propuesto** | RIG Industrial Technologies LLC (Tecnología Industrial · Ciberseguridad · Seguridad de IA) — sujeto a un acuerdo de licencia escrito por separado |
| **Sitio web** | <https://rigindustrialusa.com> |
| **Licencia Community** | Apache License 2.0 |

## Licencia

RIG Sentinel Community se distribuye bajo la [Apache License 2.0](../LICENSE). Consulte
[NOTICE](../NOTICE) para la atribución. Copyright 2026 Randy Igualguana.

La Apache License 2.0 concede sus permisos a todos los usuarios. Cualquier acuerdo
comercial separado entre el mantenedor y RIG Industrial Technologies LLC no limita los
derechos que la Apache License 2.0 otorga a los usuarios de RIG Sentinel Community.
