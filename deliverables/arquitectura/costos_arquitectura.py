#!/usr/bin/env python3
"""
SI3006 — Modelo de costos de la arquitectura propuesta (GCP, us-central1, USD/mes).

Fuentes de precio:
  [API]  Cloud Billing Catalog API (cloudbilling.googleapis.com) — consultado vía gcloud
         sobre el proyecto dw-mateo-lopera-2026. Salida cruda en precios_gcp_verificados.txt
  [DOC]  Lista de precios pública de Google Cloud (cloud.google.com/*/pricing).
         Se indica [DOC] cuando el SKU no aparece en el catálogo con ese nombre.

Salidas: costos_arquitectura.md, costos_arquitectura.csv, costos_arquitectura.png
"""
import csv

MES_H = 730  # horas promedio por mes (365*24/12)

# ---- supuestos de carga ------------------------------------------------------------
REQ_MES          = 100_000
SEGUNDOS_CPU_REQ = 0.20          # 200 ms de CPU por request
VCPU             = 1
GIB              = 1
GB_EGRESS        = 1             # GB de salida del balanceador
GIB_LOGS         = 5
GB_REGISTRY      = 1.0
SQL_VCPU         = 1
SQL_GIB          = 3.75
SQL_GB_DISCO     = 20

# ---- precios unitarios ------------------------------------------------------------
P = {
  # [API] Cloud Run — us-central1
  "run_cpu_s":        0.000024,      # Services CPU (Request-based billing)
  "run_gib_s":        0.0000025,     # Services Memory (Request-based billing)
  "run_req":          0.0000004,     # Requests (global)
  # [API] Cloud SQL for PostgreSQL — Regional, Americas
  "sql_vcpu_h":       0.0826,
  "sql_gib_h":        0.0140,
  "sql_disco_gb_mes": 0.34,          # Standard storage
  # [API] Cloud SQL for PostgreSQL — Zonal (para la variante económica)
  "sql_vcpu_h_zonal": 0.0413,
  "sql_gib_h_zonal":  0.0070,
  # [API] Secret Manager
  "sm_version_mes":   0.06,
  "sm_op":            0.000003,
  # [API] Cloud KMS
  "kms_version_mes":  0.06,
  "kms_op":           0.000003,
  # [DOC] Cloud Armor Standard
  "armor_politica":   5.00,
  "armor_regla":      1.00,
  "armor_req_millon": 0.75,
  # [DOC] Global external Application Load Balancer
  "alb_regla_h":      0.025,
  "alb_procesamiento_gb": 0.008,
  # [DOC] Serverless VPC Access (conector f1-micro, 2 instancias mínimas)
  "vpc_conector_mes": 7.00,
  # [DOC] Artifact Registry (0,5 GB gratis)
  "ar_gb_mes":        0.10,
  # [DOC] Cloud Logging (50 GiB gratis/mes)
  "logging_gib":      0.50,
  "logging_gratis_gib": 50,
  # [DOC] Cloud Monitoring (free tier amplio para este volumen)
  "monitoring_mes":   0.00,
}

# ---- gratuitos --------------------------------------------------------------------
RUN_FREE = {"cpu_s": 180_000, "gib_s": 360_000, "req": 2_000_000}

def usd(x): return round(x, 2)

# ---- cálculo ----------------------------------------------------------------------
def cloud_run():
    cpu_s = REQ_MES * SEGUNDOS_CPU_REQ * VCPU
    gib_s = REQ_MES * SEGUNDOS_CPU_REQ * GIB
    cpu = max(0, cpu_s - RUN_FREE["cpu_s"]) * P["run_cpu_s"]
    mem = max(0, gib_s - RUN_FREE["gib_s"]) * P["run_gib_s"]
    req = max(0, REQ_MES - RUN_FREE["req"]) * P["run_req"]
    return usd(cpu + mem + req)

def cloud_armor():
    return usd(P["armor_politica"] + 3 * P["armor_regla"] + REQ_MES / 1e6 * P["armor_req_millon"])

def alb():
    return usd(P["alb_regla_h"] * MES_H + GB_EGRESS * P["alb_procesamiento_gb"])

def cloud_sql(zonal=False):
    if zonal:
        c = P["sql_vcpu_h_zonal"] * SQL_VCPU + P["sql_gib_h_zonal"] * SQL_GIB
    else:
        c = P["sql_vcpu_h"] * SQL_VCPU + P["sql_gib_h"] * SQL_GIB
    return usd(c * MES_H + SQL_GB_DISCO * P["sql_disco_gb_mes"])

def secret_manager():  return usd(2 * P["sm_version_mes"] + REQ_MES * P["sm_op"])
def kms():             return usd(2 * P["kms_version_mes"] + REQ_MES * P["kms_op"])
def vpc():             return usd(P["vpc_conector_mes"])
def registry():        return usd(max(0, GB_REGISTRY - 0.5) * P["ar_gb_mes"])
def logging():         return usd(max(0, GIB_LOGS - P["logging_gratis_gib"]) * P["logging_gib"])

ESC_ACTUAL = [
    ("Cloud Run (1 vCPU / 1 GiB, 100k req)", cloud_run(),
     "Request-based billing; el uso cabe en el free tier mensual", "API"),
    ("Almacenamiento de imagen en Artifact Registry", registry(), "0,5 GB gratis", "DOC"),
    ("Cloud Logging (request logs)", logging(), "50 GiB gratis/mes", "DOC"),
]

ESC_MINIMA = ESC_ACTUAL[:1] + [
    ("Global External Application Load Balancer", alb(), "regla de reenvío 730 h + 1 GB", "DOC"),
    ("Cloud Armor Standard (1 política + 3 reglas)", cloud_armor(), "sqli, xss, rate-based-ban", "DOC"),
    ("Cloud Logging + Monitoring", logging() + P["monitoring_mes"], "free tier", "DOC"),
]

ESC_RECOMENDADA = ESC_MINIMA + [
    ("Cloud SQL PostgreSQL (Regional, 1 vCPU/3,75 GiB, 20 GB SSD)", cloud_sql(),
     "HA regional; IP privada; PITR 7 días", "API"),
    ("Serverless VPC Access (conector)", vpc(), "egress privado hacia Cloud SQL", "DOC"),
    ("Secret Manager (2 versiones + 100k accesos)", secret_manager(), "credenciales DB y claves JWT", "API"),
    ("Cloud KMS (2 claves software, CMEK)", kms(), "rotación 90 días", "API"),
    ("BigQuery / SIEM (almacenamiento y consultas)", 0.00, "10 GiB y 1 TiB/mes gratis", "DOC"),
]

ESC_ECONOMICA = ESC_MINIMA + [
    ("Cloud SQL PostgreSQL (Zonal, 1 vCPU/3,75 GiB, 20 GB SSD)", cloud_sql(zonal=True),
     "sin HA: RPO/RTO mayores", "API"),
    ("Serverless VPC Access (conector)", vpc(), "", "DOC"),
    ("Secret Manager", secret_manager(), "", "API"),
    ("Cloud KMS", kms(), "", "API"),
]


def total(esc): return usd(sum(v for _, v, _, _ in esc))

def tabla(nombre, esc, out):
    out.append(f"\n### {nombre}\n")
    out.append("| Componente | USD/mes | Notas | Fuente |")
    out.append("|---|---:|---|---|")
    for comp, v, nota, src in esc:
        out.append(f"| {comp} | {v:,.2f} | {nota} | {src} |")
    out.append(f"| **TOTAL** | **{total(esc):,.2f}** | | |")
    return total(esc)


def main():
    md = ["# Costos de la arquitectura — OWASP Juice Shop en Google Cloud",
          "",
          "Región: **us-central1**. Moneda: **USD**. Horizonte: **mensual (730 h)**.",
          "",
          "## Supuestos de carga",
          "",
          f"- {REQ_MES:,} requests/mes, {int(SEGUNDOS_CPU_REQ*1000)} ms de CPU y {GIB} GiB por request",
          f"- Cloud SQL: {SQL_VCPU} vCPU + {SQL_GIB} GiB RAM + {SQL_GB_DISCO} GB SSD, PostgreSQL 16",
          f"- {GB_EGRESS} GB de egress del balanceador, {GIB_LOGS} GiB de logs, {GB_REGISTRY} GB de imagen",
          "- Precios marcados **[API]** provienen del catálogo oficial de facturación consultado con gcloud;",
          "  los marcados **[DOC]** provienen de la lista de precios pública de Google Cloud.",
          ""]
    t0 = tabla("0 · Estado actual (solo Cloud Run público)", ESC_ACTUAL, md)
    t1 = tabla("1 · Núcleo mínimo seguro (ALB + Cloud Armor + IAP)", ESC_MINIMA, md)
    t2 = tabla("2 · Arquitectura recomendada (defensa en profundidad)", ESC_RECOMENDADA, md)
    t3 = tabla("3 · Variante económica (Cloud SQL zonal, sin HA)", ESC_ECONOMICA, md)

    md += ["", "## Resumen ejecutivo", "",
           "| Escenario | USD/mes | USD/año | Δ vs. actual |",
           "|---|---:|---:|---:|",
           f"| 0 · Actual (inseguro) | {t0:,.2f} | {t0*12:,.2f} | — |",
           f"| 1 · Núcleo mínimo | {t1:,.2f} | {t1*12:,.2f} | +{t1-t0:,.2f}/mes |",
           f"| 2 · Recomendada | {t2:,.2f} | {t2*12:,.2f} | +{t2-t0:,.2f}/mes |",
           f"| 3 · Económica | {t3:,.2f} | {t3*12:,.2f} | +{t3-t0:,.2f}/mes |",
           "",
           f"El salto de **{t0:,.2f} → {t1:,.2f} USD/mes** (≈ **{(t1-t0)*12:,.0f} USD/año**) es el precio de poner",
           "el WAF y el control de identidad delante de la aplicación. Bloquear la inyección SQL no",
           "requiere tocar el código: la regla `sqli-v33-stable` de Cloud Armor ya está creada en el",
           "proyecto (`gcloud compute security-policies describe juice-shop-waf`).",
           "",
           "> Referencia externa de impacto: el costo medio global de una brecha de datos se estima en",
           "> **4,44 M USD** (IBM *Cost of a Data Breach Report 2025*). El control cuesta ~0,3 % de esa cifra.",
           ""]
    open("costos_arquitectura.md", "w").write("\n".join(md))

    with open("costos_arquitectura.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["escenario", "componente", "usd_mes", "nota", "fuente_precio"])
        for nombre, esc in [("actual", ESC_ACTUAL), ("minima", ESC_MINIMA),
                            ("recomendada", ESC_RECOMENDADA), ("economica", ESC_ECONOMICA)]:
            for comp, v, nota, src in esc:
                w.writerow([nombre, comp, v, nota, src])
            w.writerow([nombre, "TOTAL", total(esc), "", ""])

    # gráfico comparativo
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        nombres = ["Actual\n(inseguro)", "Núcleo mínimo\nALB + WAF + IAP",
                   "Económica\nSQL zonal", "Recomendada\ndefensa en profundidad"]
        vals = [t0, t1, t3, t2]
        cols = ["#c5221f", "#1a73e8", "#188038", "#174ea6"]
        fig, ax = plt.subplots(figsize=(9.2, 4.6))
        b = ax.bar(nombres, vals, color=cols, width=0.62)
        for r, v in zip(b, vals):
            ax.text(r.get_x() + r.get_width() / 2, v + max(vals) * 0.02,
                    f"USD {v:,.2f}\n~{v*12:,.0f}/año", ha="center", va="bottom",
                    fontsize=9.5, fontweight="bold", color="#0f172a")
        ax.set_ylabel("USD / mes", fontsize=10)
        ax.set_title("Costo mensual estimado por escenario (us-central1, 100k req/mes)",
                     fontsize=11.5, fontweight="bold", color="#0f172a", pad=12)
        ax.set_ylim(0, max(vals) * 1.28)
        ax.spines[["top", "right"]].set_visible(False)
        ax.tick_params(labelsize=9)
        ax.grid(axis="y", alpha=0.25)
        ax.set_axisbelow(True)
        fig.tight_layout()
        fig.savefig("costos_arquitectura.png", dpi=190, facecolor="white")
        print("ok: costos_arquitectura.png")
    except Exception as e:  # pragma: no cover
        print("grafico omitido:", e)

    print(open("costos_arquitectura.md").read()[-1400:])


if __name__ == "__main__":
    main()
