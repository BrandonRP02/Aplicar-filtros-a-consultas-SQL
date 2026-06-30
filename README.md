# Aplicar filtros a consultas SQL

## Descripción del proyecto

Como analista de ciberseguridad, parte de mi función implica investigar eventos de seguridad para garantizar la integridad de los sistemas de la organización. En este proyecto, demuestro cómo utilicé **SQL con filtros avanzados** para analizar registros de inicio de sesión y gestionar actualizaciones críticas en los equipos de los empleados.

Las consultas se ejecutaron sobre dos tablas clave de la base de datos de la organización:

| Tabla | Descripción |
|---|---|
| `log_in_attempts` | Registros de todos los intentos de autenticación, incluyendo marcas de tiempo, estado de éxito/fallo y ubicación geográfica. |
| `employees` | Información de los empleados, incluyendo departamento asignado y ubicación de oficina. |

A través de operadores como `AND`, `OR`, `NOT` y `LIKE`, logré aislar patrones de actividad sospechosa, verificar ubicaciones geográficas y segmentar empleados para el despliegue de parches de seguridad.

---

## Recuperar intentos de inicio de sesión fallidos fuera del horario laboral

Se identificó un incidente potencial de seguridad que ocurrió fuera del horario laboral (después de las 18:00). Para investigar los intentos de inicio de sesión fallidos durante ese periodo, ejecuté la siguiente consulta:

```sql
SELECT *
FROM log_in_attempts
WHERE login_time > '18:00:00' AND success = FALSE;
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta de intentos fallidos fuera de horario](images/sql-after-hours.png)

**Análisis:** La cláusula `WHERE` combina dos condiciones mediante el operador `AND`, lo que garantiza que **ambas** se cumplan simultáneamente. La primera condición, `login_time > '18:00:00'`, filtra los registros ocurridos después de las 18:00. La segunda, `success = FALSE`, aísla exclusivamente los intentos de autenticación fallidos. Esta correlación es un patrón estándar en la detección de ataques de fuerza bruta fuera del horario operativo.

---

## Recuperar intentos de inicio de sesión en fechas específicas

Se reportó un evento sospechoso el 2022-05-09. Se requirió investigar toda la actividad de inicio de sesión de esa fecha y del día anterior (2022-05-08). La consulta utilizada fue:

```sql
SELECT *
FROM log_in_attempts
WHERE login_date = '2022-05-09' OR login_date = '2022-05-08';
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta por fechas específicas](images/sql-specific-dates.png)

**Análisis:** El operador `OR` permite evaluar múltiples condiciones de forma inclusiva: el registro se devuelve si cumple **al menos una** de ellas. En este caso, la consulta captura toda la actividad registrada el 8 o el 9 de mayo de 2022. En respuesta a incidentes, es una práctica habitual ampliar la ventana temporal de análisis para identificar indicadores de compromiso (IoC) que puedan preceder al evento principal.

---

## Recuperar intentos de inicio de sesión fuera de México

La investigación determinó que la actividad sospechosa no se originó en México. Para aislar los intentos provenientes de otros países, apliqué la siguiente consulta:

```sql
SELECT *
FROM log_in_attempts
WHERE NOT country LIKE 'MEX%';
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta excluyendo México](images/sql-not-mexico.png)

**Análisis:** Esta consulta combina el operador `NOT` con la función de coincidencia de patrones `LIKE`. Dado que la columna `country` almacena la ubicación como `"MEX"` o `"MEXICO"`, el comodín `%` en el patrón `'MEX%'` captura cualquier cadena que comience con esas tres letras. Al anteponer `NOT`, se invierten los resultados, excluyendo todo registro de origen mexicano. Esta técnica es esencial cuando los datos presentan inconsistencias de formato y se requiere un filtrado robusto.

---

## Recuperar empleados del departamento de Marketing

Se programó una actualización de seguridad para los equipos del departamento de Marketing ubicados en el edificio Este. Para identificar a los empleados afectados, utilicé:

```sql
SELECT *
FROM employees
WHERE department = 'Marketing' AND office LIKE 'East-%';
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta de empleados en Marketing](images/sql-marketing-east.png)

**Análisis:** La consulta emplea `AND` para aplicar dos filtros estrictos de forma simultánea. La condición `department = 'Marketing'` delimita el departamento objetivo. La condición `office LIKE 'East-%'` utiliza coincidencia de patrones para capturar todas las oficinas cuya designación comienza con `"East-"`, independientemente del número de habitación (por ejemplo, `East-170`, `East-320`). Esta segmentación precisa es fundamental para garantizar que los parches de seguridad se desplieguen únicamente en la infraestructura correcta.

---

## Recuperar empleados en Finanzas o Ventas

El equipo de seguridad también necesitó aplicar una actualización diferente a los equipos de los departamentos de Finanzas y Ventas. La consulta empleada fue:

```sql
SELECT *
FROM employees
WHERE department = 'Sales' OR department = 'Finance';
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta de empleados en Finanzas o Ventas](images/sql-finance-sales.png)

**Análisis:** El operador `OR` evalúa cada registro de forma inclusiva, devolviéndolo si la columna `department` coincide con `"Sales"` **o** con `"Finance"`. Esto permite abarcar múltiples departamentos en una sola instrucción, eliminando la necesidad de ejecutar consultas independientes y reduciendo la complejidad operativa durante el despliegue de actualizaciones.

---

## Recuperar empleados que no pertenecen a Tecnología de la Información

Finalmente, se requirió aplicar una actualización de seguridad adicional a todos los empleados que **no** pertenecen al departamento de Tecnología de la Información, ya que este equipo ya había recibido la actualización previamente. La consulta fue:

```sql
SELECT *
FROM employees
WHERE NOT department = 'Information Technology';
```

La siguiente captura muestra un fragmento de la salida generada por esta consulta:

![Consulta excluyendo TI](images/sql-not-it.png)

**Análisis:** El operador `NOT` simplifica la lógica de exclusión. En lugar de enumerar todos los departamentos restantes con múltiples condiciones `OR`, se niega la única condición que se desea excluir. Esta práctica es más limpia, escalable y menos propensa a errores, especialmente en organizaciones con una gran cantidad de departamentos.

---

## Resumen

En este proyecto, apliqué filtros SQL estructurales para cumplir dos objetivos críticos de seguridad:

1. **Investigación de incidentes:** Se identificaron intentos de inicio de sesión anómalos filtrando por horario, fecha y ubicación geográfica, lo que permitió aislar patrones sospechosos consistentes con posibles vectores de ataque.

2. **Gestión de actualizaciones:** Se segmentaron los empleados por departamento y edificio para garantizar un despliegue preciso de parches de seguridad en la infraestructura correcta.

Los operadores clave utilizados fueron:

| Operador | Función | Caso de uso |
|---|---|---|
| `AND` | Combina condiciones que deben cumplirse simultáneamente. | Filtrar por horario **y** estado de autenticación. |
| `OR` | Incluye registros que cumplan al menos una condición. | Buscar en múltiples fechas o departamentos. |
| `NOT` | Excluye registros que coincidan con una condición. | Descartar un país o departamento específico. |
| `LIKE` | Filtra por coincidencia de patrones con comodines (`%`). | Identificar ubicaciones con formato variable. |

> **Nota sobre rendimiento:** En un entorno de producción con grandes volúmenes de datos, sería recomendable crear **índices** en las columnas que se filtran con mayor frecuencia (`login_time`, `login_date`, `country`, `department`, `office`) para optimizar los tiempos de ejecución de estas consultas y minimizar la carga sobre la base de datos.
