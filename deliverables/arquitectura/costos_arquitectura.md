# Costos de la arquitectura — OWASP Juice Shop en Google Cloud

Región: **us-central1**. Moneda: **USD**. Horizonte: **mensual (730 h)**.

## Supuestos de carga

- 100,000 requests/mes, 200 ms de CPU y 1 GiB por request
- Cloud SQL: 1 vCPU + 3.75 GiB RAM + 20 GB SSD, PostgreSQL 16
- 1 GB de egress del balanceador, 5 GiB de logs, 1.0 GB de imagen
- Precios marcados **[API]** provienen del catálogo oficial de facturación consultado con gcloud;
  los marcados **[DOC]** provienen de la lista de precios pública de Google Cloud.


### 0 · Estado actual (solo Cloud Run público)

| Componente | USD/mes | Notas | Fuente |
|---|---:|---|---|
| Cloud Run (1 vCPU / 1 GiB, 100k req) | 0.00 | Request-based billing; el uso cabe en el free tier mensual | API |
| Almacenamiento de imagen en Artifact Registry | 0.05 | 0,5 GB gratis | DOC |
| Cloud Logging (request logs) | 0.00 | 50 GiB gratis/mes | DOC |
| **TOTAL** | **0.05** | | |

### 1 · Núcleo mínimo seguro (ALB + Cloud Armor + IAP)

| Componente | USD/mes | Notas | Fuente |
|---|---:|---|---|
| Cloud Run (1 vCPU / 1 GiB, 100k req) | 0.00 | Request-based billing; el uso cabe en el free tier mensual | API |
| Global External Application Load Balancer | 18.26 | regla de reenvío 730 h + 1 GB | DOC |
| Cloud Armor Standard (1 política + 3 reglas) | 8.07 | sqli, xss, rate-based-ban | DOC |
| Cloud Logging + Monitoring | 0.00 | free tier | DOC |
| **TOTAL** | **26.33** | | |

### 2 · Arquitectura recomendada (defensa en profundidad)

| Componente | USD/mes | Notas | Fuente |
|---|---:|---|---|
| Cloud Run (1 vCPU / 1 GiB, 100k req) | 0.00 | Request-based billing; el uso cabe en el free tier mensual | API |
| Global External Application Load Balancer | 18.26 | regla de reenvío 730 h + 1 GB | DOC |
| Cloud Armor Standard (1 política + 3 reglas) | 8.07 | sqli, xss, rate-based-ban | DOC |
| Cloud Logging + Monitoring | 0.00 | free tier | DOC |
| Cloud SQL PostgreSQL (Regional, 1 vCPU/3,75 GiB, 20 GB SSD) | 105.42 | HA regional; IP privada; PITR 7 días | API |
| Serverless VPC Access (conector) | 7.00 | egress privado hacia Cloud SQL | DOC |
| Secret Manager (2 versiones + 100k accesos) | 0.42 | credenciales DB y claves JWT | API |
| Cloud KMS (2 claves software, CMEK) | 0.42 | rotación 90 días | API |
| BigQuery / SIEM (almacenamiento y consultas) | 0.00 | 10 GiB y 1 TiB/mes gratis | DOC |
| **TOTAL** | **139.59** | | |

### 3 · Variante económica (Cloud SQL zonal, sin HA)

| Componente | USD/mes | Notas | Fuente |
|---|---:|---|---|
| Cloud Run (1 vCPU / 1 GiB, 100k req) | 0.00 | Request-based billing; el uso cabe en el free tier mensual | API |
| Global External Application Load Balancer | 18.26 | regla de reenvío 730 h + 1 GB | DOC |
| Cloud Armor Standard (1 política + 3 reglas) | 8.07 | sqli, xss, rate-based-ban | DOC |
| Cloud Logging + Monitoring | 0.00 | free tier | DOC |
| Cloud SQL PostgreSQL (Zonal, 1 vCPU/3,75 GiB, 20 GB SSD) | 56.11 | sin HA: RPO/RTO mayores | API |
| Serverless VPC Access (conector) | 7.00 |  | DOC |
| Secret Manager | 0.42 |  | API |
| Cloud KMS | 0.42 |  | API |
| **TOTAL** | **90.28** | | |

## Resumen ejecutivo

| Escenario | USD/mes | USD/año | Δ vs. actual |
|---|---:|---:|---:|
| 0 · Actual (inseguro) | 0.05 | 0.60 | — |
| 1 · Núcleo mínimo | 26.33 | 315.96 | +26.28/mes |
| 2 · Recomendada | 139.59 | 1,675.08 | +139.54/mes |
| 3 · Económica | 90.28 | 1,083.36 | +90.23/mes |

El salto de **0.05 → 26.33 USD/mes** (≈ **315 USD/año**) es el precio de poner
el WAF y el control de identidad delante de la aplicación. Bloquear la inyección SQL no
requiere tocar el código: la regla `sqli-v33-stable` de Cloud Armor ya está creada en el
proyecto (`gcloud compute security-policies describe juice-shop-waf`).

> Referencia externa de impacto: el costo medio global de una brecha de datos se estima en
> **4,44 M USD** (IBM *Cost of a Data Breach Report 2025*). El control cuesta ~0,3 % de esa cifra.
