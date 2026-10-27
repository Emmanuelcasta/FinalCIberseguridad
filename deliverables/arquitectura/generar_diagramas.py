#!/usr/bin/env python3
"""
SI3006 - Genera los diagramas de arquitectura (SVG + PNG) para Juice Shop.
  salida: arquitectura_actual.svg/.png  y  arquitectura_segura.svg/.png
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import matplotlib.patheffects as pe

# ---- paleta -------------------------------------------------------------------------
INK      = "#0f172a"
MUTED    = "#64748b"
BG       = "#ffffff"
GCP_BLUE = "#1a73e8"
GCP_DARK = "#174ea6"
GREEN    = "#188038"
RED      = "#c5221f"
AMBER    = "#b06000"
GREY_BOX = "#f1f5f9"
BORDER   = "#cbd5e1"


def box(ax, x, y, w, h, title, sub=None, fc="#ffffff", ec=BORDER, tc=INK, fs=10.5, subsize=8.2,
        lw=1.3, ls="-", badge=None, badge_color=None, radius=0.02):
    p = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}",
                       linewidth=lw, edgecolor=ec, facecolor=fc, linestyle=ls, zorder=3)
    ax.add_patch(p)
    ty = y + h / 2 + (0.021 if sub else 0)
    ax.text(x + w / 2, ty, title, ha="center", va="center", fontsize=fs, color=tc,
            fontweight="bold", zorder=4)
    if sub:
        ax.text(x + w / 2, y + h / 2 - 0.026, sub, ha="center", va="center",
                fontsize=subsize, color=MUTED, zorder=4, linespacing=1.35)
    if badge:
        ax.text(x + w - 0.012, y + h - 0.018, badge, ha="right", va="top", fontsize=7.4,
                color="white", fontweight="bold", zorder=5,
                bbox=dict(boxstyle="round,pad=0.28", fc=badge_color or RED, ec="none"))


def arrow(ax, p1, p2, color=GCP_BLUE, lw=1.6, style="-|>", ls="-", rad=0.0, label=None,
          lcolor=None, lfs=7.6, conn=None):
    cs = conn or f"arc3,rad={rad}"
    a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=13, linewidth=lw,
                        color=color, linestyle=ls, connectionstyle=cs, zorder=2,
                        shrinkA=2, shrinkB=2)
    ax.add_patch(a)
    if label:
        mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
        ax.text(mx, my + 0.016, label, ha="center", va="bottom", fontsize=lfs,
                color=lcolor or color, fontweight="bold", zorder=6,
                path_effects=[pe.withStroke(linewidth=3, foreground="white")])


def band(ax, x, y, w, h, label, color=GCP_BLUE):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=color, alpha=0.055, zorder=1,
                           edgecolor=color, linewidth=1.0, linestyle=(0, (5, 4))))
    ax.text(x + 0.004, y + h + 0.004, label, ha="left", va="bottom", fontsize=8.4,
            color=color, fontweight="bold", zorder=2, alpha=0.95)


def canvas(w=16.0, h=9.0):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    fig.patch.set_facecolor(BG)
    return fig, ax


def save(fig, name):
    for ext in ("svg", "png"):
        fig.savefig(f"{name}.{ext}", dpi=190, bbox_inches="tight", facecolor=BG,
                    pad_inches=0.16)
    plt.close(fig)
    print("ok:", name)


# =====================================================================================
# 1) ARQUITECTURA ACTUAL (INSEGURA)
# =====================================================================================
def actual():
    fig, ax = canvas()
    ax.text(0, 1.035, "Arquitectura ACTUAL — despliegue en Cloud Run (insegura)",
            fontsize=17, fontweight="bold", color=INK, va="bottom")
    ax.text(0, 1.005, "OWASP Juice Shop v20.3.0 · proyecto dw-mateo-lopera-2026 · us-central1 · estado real del servicio",
            fontsize=9.5, color=MUTED, va="bottom")

    band(ax, 0.02, 0.30, 0.20, 0.52, "INTERNET", RED)
    band(ax, 0.255, 0.30, 0.505, 0.52, "PERÍMETRO  ·  sin control alguno", RED)
    band(ax, 0.795, 0.30, 0.185, 0.52, "PROYECTO GCP", AMBER)
    band(ax, 0.02, 0.055, 0.96, 0.195, "OBSERVABILIDAD  ·  pasiva", AMBER)

    box(ax, 0.035, 0.585, 0.17, 0.115, "Atacante", "Internet\n(no autenticado)", fc="#fdecea", ec=RED, tc=RED)
    box(ax, 0.035, 0.415, 0.17, 0.115, "Usuario víctima", "navegador", fc=GREY_BOX)

    box(ax, 0.285, 0.55, 0.44, 0.16,
        "https://juice-shop-si3006-…run.app   (invoker: ALL USERS)",
        "Cloud Run  ·  containerConcurrency 80  ·  maxScale 1  ·  ingress = all\n"
        "SA juice-shop-runtime  ·  1 vCPU / 1 GiB  ·  ejecución pública sin identidad",
        fc="#fff7e0", ec=AMBER, tc=AMBER, fs=10.2)
    ax.text(0.505, 0.475, "😈   superficie de ataque = código de la aplicación",
            ha="center", va="center", fontsize=9.4, color=RED, fontweight="bold")

    box(ax, 0.285, 0.345, 0.20, 0.10, "SQLite embebida", "volumen del contenedor\n(sin cifrar, sin respaldo gestionado)",
        fc="#fdecea", ec=RED, tc=RED, fs=9.4)
    box(ax, 0.525, 0.345, 0.20, 0.10, "Secretos en el repo", "claves JWT RSA planas\nencryptionkeys/  (sin KMS)",
        fc="#fdecea", ec=RED, tc=RED, fs=9.4)

    box(ax, 0.83, 0.55, 0.135, 0.145, "Cloud Logging", "request logs\nretención por defecto\nsin alertas", fs=9.2)
    box(ax, 0.83, 0.365, 0.135, 0.145, "Artifact Registry", "imagen sin escaneo\nobligatorio", fc=GREY_BOX, fs=9.2)

    box(ax, 0.06, 0.095, 0.20, 0.105, "Cloud Logging (sink)", "audit / request logs", fc="#fff7e0", ec=AMBER, fs=9.4)
    box(ax, 0.30, 0.095, 0.22, 0.105, "sin SIEM ni correlación", "nadie mira los logs", fc="#fdecea", ec=RED, tc=RED, fs=9.4)
    box(ax, 0.56, 0.095, 0.18, 0.105, "sin WAF / sin IAP", "no hay control\ncompensatorio", fc="#fdecea", ec=RED, tc=RED, fs=9.4)
    box(ax, 0.775, 0.095, 0.19, 0.105, "sin DevSecOps", "build → deploy directo", fc="#fdecea", ec=RED, tc=RED, fs=9.4)

    arrow(ax, (0.205, 0.643), (0.285, 0.63), RED, 2.0, label="HTTPS público", lfs=8.0)
    arrow(ax, (0.205, 0.472), (0.285, 0.585), GCP_BLUE, 1.6)
    arrow(ax, (0.505, 0.55), (0.505, 0.445), MUTED, 1.3, ls=(0, (4, 3)))
    arrow(ax, (0.725, 0.60), (0.83, 0.62), MUTED, 1.2, ls=(0, (4, 3)))
    arrow(ax, (0.897, 0.55), (0.897, 0.51), MUTED, 1.2, ls=(0, (4, 3)))

    ax.text(0.5, 0.005,
            "Hallazgos de la revisión:  ingress=all  ·  allUsers → run.invoker  ·  sin Cloud Armor  ·  sin IAP  ·  sin rate limit en /rest/user/login\n"
            "sin Cloud SQL gestionado  ·  sin CMEK  ·  sin SAST en el pipeline  ·  logs sin sink a SIEM  ·  sin presupuesto/alerta de anomalía",
            ha="center", va="bottom", fontsize=8.2, color=MUTED, linespacing=1.5)
    save(fig, "arquitectura_actual")


# =====================================================================================
# 2) ARQUITECTURA SEGURA PROPUESTA
# =====================================================================================
def segura():
    fig, ax = canvas(h=9.7)
    ax.text(0, 1.035, "Arquitectura SEGURA propuesta — defensa en profundidad (KISS)",
            fontsize=17, fontweight="bold", color=INK, va="bottom")
    ax.text(0, 1.005, "Mismo servicio, 6 controles nuevos. Toda la mitigación de CWE-89 ocurre sin tocar una línea de código.",
            fontsize=9.5, color=MUTED, va="bottom")

    band(ax, 0.015, 0.615, 0.155, 0.335, "USUARIO", MUTED)
    band(ax, 0.185, 0.615, 0.335, 0.335, "BORDE · capas 1-3", RED)
    band(ax, 0.535, 0.615, 0.245, 0.335, "CÓMPUTO · capa 4", GCP_BLUE)
    band(ax, 0.795, 0.615, 0.190, 0.335, "DATOS · capa 5", GREEN)
    band(ax, 0.185, 0.325, 0.800, 0.245, "OBSERVABILIDAD Y RESPUESTA · capa 6  —  BLUE TEAM", AMBER)
    band(ax, 0.015, 0.045, 0.970, 0.235, "DEVSECOPS · capa 7  —  SHIFT LEFT", "#7c3aed")

    # ---------------- USUARIO ----------------
    box(ax, 0.028, 0.855, 0.130, 0.070, "Empleado / Partner", "identidad corporativa", fs=8.4)
    box(ax, 0.028, 0.740, 0.130, 0.070, "Atacante", "Internet", fc="#fdecea", ec=RED, tc=RED, fs=8.6)

    # ---------------- BORDE ----------------
    box(ax, 0.200, 0.848, 0.140, 0.072, "Cloud DNS", "juice-sh.op · zona gestionada", fs=9.0)
    box(ax, 0.200, 0.760, 0.140, 0.072, "Identity-Aware Proxy", "IAM + MFA + access levels", fs=8.8,
        fc="#e8f0fe", ec=GCP_DARK, tc=GCP_DARK)
    box(ax, 0.355, 0.760, 0.150, 0.160, "Global External\nApplication Load Balancer",
        "HTTPS 443 · TLS 1.3\ncert. gestionado · HSTS\nServerless NEG", fs=9.4, subsize=7.6)
    box(ax, 0.200, 0.630, 0.305, 0.105,
        "Cloud Armor  ·  security-policy juice-shop-waf",
        "1000  evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})  → deny 403\n"
        "1100  xss-v33-stable         2000  rate-based-ban 20 req/min/IP, ban 600 s",
        fc="#fdecea", ec=RED, tc=RED, fs=9.0, subsize=7.6, badge="WAF", badge_color=RED)

    # ---------------- CÓMPUTO ----------------
    box(ax, 0.550, 0.735, 0.215, 0.195, "Cloud Run — juice-shop",
        "ingress = internal-and-cloud-load-balancing\nmin-instances 1 · maxScale 3 · 1 vCPU / 1 GiB\n"
        "SA juice-shop-runtime sin roles de proyecto\ncontenedor non-root · rootfs read-only",
        fc="#e8f0fe", ec=GCP_DARK, tc=GCP_DARK, fs=10.2, subsize=7.5,
        badge="CÓMPUTO", badge_color=GCP_BLUE)
    box(ax, 0.550, 0.638, 0.215, 0.078, "Serverless VPC Access",
        "conector en subred privada 10.10.20.0/28\nsin IP pública de salida", fs=9.2, subsize=7.4)

    # ---------------- DATOS ----------------
    box(ax, 0.810, 0.848, 0.160, 0.072, "Secret Manager", "credenciales DB + claves JWT", fs=9.0,
        fc="#e6f4ea", ec=GREEN, tc=GREEN)
    box(ax, 0.810, 0.745, 0.160, 0.088, "Cloud KMS (CMEK)", "rotación 90 días\ncifra SQL + Registry", fs=9.0,
        fc="#e6f4ea", ec=GREEN, tc=GREEN, subsize=7.6)
    box(ax, 0.810, 0.638, 0.160, 0.092, "Cloud SQL PostgreSQL", "IP privada · sslmode=require\nPITR 7 días · usuario de app\nsin privilegios de DDL",
        fc="#e6f4ea", ec=GREEN, tc=GREEN, fs=9.0, subsize=7.4)

    # ---------------- OBSERVABILIDAD ----------------
    box(ax, 0.200, 0.415, 0.150, 0.100, "Cloud Logging", "request + audit logs\nlog sink con filtros", fs=9.2, subsize=7.6)
    box(ax, 0.368, 0.415, 0.158, 0.100, "BigQuery / SIEM", "Wazuh · Chronicle\nreglas Sigma correladas", fs=9.2, subsize=7.6)
    box(ax, 0.545, 0.415, 0.152, 0.100, "Cloud Monitoring", "SLO 99,9 %\nlog-based metric\n'sqli_attempts'", fs=9.2, subsize=7.4)
    box(ax, 0.715, 0.415, 0.130, 0.100, "Pub/Sub → SOAR", "playbook de\nauto-remediación", fs=9.2, subsize=7.4)
    box(ax, 0.862, 0.415, 0.108, 0.100, "On-call", "PagerDuty / Teams", fs=9.0, subsize=7.4)

    # ---------------- DEVSECOPS ----------------
    bx = [(0.032, 0.140, "1 · Code", "revisión por pares\n+ threat model"),
          (0.190, 0.155, "2 · Build / SAST", "Semgrep p/sql-injection\ncomo gate BLOQUEANTE"),
          (0.361, 0.155, "3 · SCA + SBOM", "npm audit · CycloneDX\nTrivy / Grype · fail HIGH"),
          (0.532, 0.165, "4 · Container / IaC", "scan en Artifact Registry\nCheckov / tfsec · cosign"),
          (0.713, 0.145, "5 · Deploy", "canary 10 % → 100 %\nrollback automático"),
          (0.874, 0.098, "6 · Runtime", "DAST OWASP ZAP\n+ pentest trimestral")]
    for x, w, t, sub in bx:
        box(ax, x, 0.130, w, 0.110, t, sub, fc="#f3e8ff", ec="#7c3aed", tc="#7c3aed", fs=9.2, subsize=7.2)
    for i in range(len(bx) - 1):
        x1 = bx[i][0] + bx[i][1]; x2 = bx[i + 1][0]
        arrow(ax, (x1, 0.185), (x2, 0.185), "#7c3aed", 1.4)
    ax.text(0.5, 0.080,
            "El gate SAST detecta la inyección SQL en routes/login.ts y routes/search.ts y rompe el build: ninguna imagen vulnerable llega a Cloud Run.",
            ha="center", va="center", fontsize=8.2, color="#7c3aed", style="italic")

    # ---------------- FLUJOS ----------------
    arrow(ax, (0.158, 0.890), (0.200, 0.890), GCP_BLUE, 1.7)
    arrow(ax, (0.158, 0.775), (0.200, 0.770), RED, 1.7, ls=(0, (4, 2)))
    arrow(ax, (0.340, 0.884), (0.355, 0.884), GCP_BLUE, 1.7)
    arrow(ax, (0.340, 0.796), (0.355, 0.806), GCP_DARK, 1.5)
    arrow(ax, (0.430, 0.760), (0.430, 0.735), RED, 1.8)
    arrow(ax, (0.505, 0.700), (0.550, 0.745), RED, 1.9, label="NEG", lfs=7.2, lcolor=RED)
    arrow(ax, (0.657, 0.735), (0.657, 0.716), GCP_BLUE, 1.4)
    arrow(ax, (0.765, 0.677), (0.810, 0.677), GREEN, 1.7)
    arrow(ax, (0.765, 0.884), (0.810, 0.884), GREEN, 1.5, label="IAM", lfs=7.2, lcolor=GREEN)
    arrow(ax, (0.657, 0.735), (0.657, 0.716), GCP_BLUE, 1.4)

    # logs / métricas: canal vertical entre las bandas CÓMPUTO y DATOS
    arrow(ax, (0.775, 0.760), (0.620, 0.520), MUTED, 1.3, ls=(0, (4, 3)),
          conn="angle,angleA=-90,angleB=0,rad=6", label="logs + métricas", lfs=7.0)
    arrow(ax, (0.352, 0.465), (0.368, 0.465), AMBER, 1.3)
    arrow(ax, (0.526, 0.465), (0.545, 0.465), AMBER, 1.3)
    arrow(ax, (0.697, 0.465), (0.715, 0.465), AMBER, 1.3)
    arrow(ax, (0.845, 0.465), (0.862, 0.465), AMBER, 1.3)
    # auto-remediación: SOAR → Cloud Armor (ban de IP)
    arrow(ax, (0.780, 0.518), (0.330, 0.628), AMBER, 1.4, ls=(0, (5, 3)), rad=0.10)
    ax.text(0.560, 0.585, "playbook: ban de IP en Cloud Armor", fontsize=7.2, color=AMBER,
            ha="center", va="center", fontweight="bold",
            path_effects=[pe.withStroke(linewidth=3, foreground="white")])

    ax.text(0.5, 0.012,
            "KISS: el núcleo mínimo son 3 piezas — ALB + Cloud Armor (regla sqli) + IAP. Cloud SQL, KMS y el SIEM son incrementales según presupuesto y criticidad.",
            ha="center", va="bottom", fontsize=8.4, color=MUTED, style="italic")
    save(fig, "arquitectura_segura")


if __name__ == "__main__":
    actual()
    segura()
