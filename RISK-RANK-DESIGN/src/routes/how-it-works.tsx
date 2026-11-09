import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ArrowRight,
  ScanLine,
  Database,
  Layers,
  BrainCircuit,
  ListOrdered,
  FileText,
  Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageTitle } from "@/components/rr/shell";

export const Route = createFileRoute("/how-it-works")({
  head: () => ({
    meta: [
      { title: "How it works · RiskRank-VAPT" },
      {
        name: "description",
        content:
          "From scanner findings to contextual risk ranking: RiskRank-VAPT research workflow, security signals and current dashboard capabilities.",
      },
      { property: "og:title", content: "How it works · RiskRank-VAPT" },
      {
        property: "og:description",
        content:
          "Understand the proposed research pipeline and how exported results are explored in this dashboard.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: HowItWorks,
});

const steps = [
  {
    icon: ScanLine,
    title: "Collect findings",
    location: "Research pipeline",
    body: "Run a vulnerability scanner in a controlled, authorized security-testing environment and collect its findings.",
    output: "Vulnerability findings",
  },
  {
    icon: Database,
    title: "Enrich the data",
    location: "Research pipeline",
    body: "Add CVSS severity, exploit availability, known-exploited status and asset information to the findings.",
    output: "Context-enriched records",
  },
  {
    icon: Layers,
    title: "Extract features",
    location: "Research pipeline",
    body: "Prepare the vulnerability and context information as features for the machine learning model.",
    output: "Model inputs",
  },
  {
    icon: BrainCircuit,
    title: "Generate risk scores",
    location: "Research pipeline",
    body: "The proposed model uses those features to predict risk. Training and inference take place in the external Python workflow, not in this dashboard.",
    output: "Exported risk scores",
  },
  {
    icon: ListOrdered,
    title: "Assign priority",
    location: "Research pipeline",
    body: "Produce a priority level and ranking for each vulnerability. This dashboard reads the exported score and label without choosing score thresholds.",
    output: "Scored vulnerability CSV",
  },
  {
    icon: FileText,
    title: "Review and report",
    location: "This dashboard",
    body: "Upload the scored CSV, inspect the findings and context, compare exported evaluation metrics, and download the filtered records.",
    output: "Reviewed findings and CSV report",
  },
];
const glossary = [
  [
    "CVE / NVD",
    "CVE identifies a publicly disclosed vulnerability; NVD supplies vulnerability information. A CVE identifier is not itself a risk score.",
  ],
  [
    "CVSS",
    "A standardized measure of vulnerability severity. Severity does not, by itself, account for all the urgency of a finding in your environment.",
  ],
  [
    "EPSS",
    "An estimate of exploitation probability. Its scale and values are retained from the exported file; it is not the same as CVSS severity.",
  ],
  [
    "CISA KEV",
    "Membership in CISA’s Known Exploited Vulnerabilities catalog indicates known exploitation. It does not prove that your own asset was compromised.",
  ],
  [
    "Exploit availability",
    "Context about whether exploit information or code is available. This is an enrichment input in the proposed pipeline, not a live check made by this dashboard.",
  ],
  [
    "Exposure and asset context",
    "Whether an asset is internet-facing and how important it is to the environment. Context helps distinguish findings with otherwise similar severity.",
  ],
  [
    "Risk score / Adaptive PSSS",
    "The score produced by your external workflow. The dashboard accepts headers such as risk_score, adaptive_psss or psss. The presentation does not specify a formula, model weights or priority thresholds.",
  ],
  [
    "ATT&CK / UCKC",
    "Optional signal columns supported by the existing dashboard views. Their definitions and encoding must come from your research pipeline; the attached presentation does not describe them.",
  ],
];

function HowItWorks() {
  return (
    <div className="max-w-5xl">
      <PageTitle
        title="How it works"
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/project">
              Project details
              <ArrowRight />
            </Link>
          </Button>
        }
      />
      <section className="pb-7">
        <h2 className="text-2xl font-semibold">From findings to remediation priorities</h2>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-muted-foreground">
          More context → better prioritization is the presentation’s core idea. The research
          pipeline produces scores and priority labels; this web dashboard makes the exported
          results available for review.
        </p>
      </section>
      <div className="mb-7 flex items-start gap-3 border-y border-border bg-muted/40 px-4 py-4">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" />
        <p className="text-sm leading-6">
          <strong>Current boundary:</strong> this dashboard does not scan targets, fetch live
          intelligence, train a model, calculate new risk scores, validate exploits or re-test
          fixes. Those activities are separate from the uploaded-result views.
        </p>
      </div>
      <section className="pb-8">
        <h2 className="mb-5 text-lg font-semibold">The system workflow</h2>
        <ol className="grid gap-x-8 md:grid-cols-2">
          {steps.map(({ icon: Icon, title, location, body, output }, index) => (
            <li key={title} className="border-t border-border py-5">
              <div className="flex items-center gap-3">
                <span className="text-xs tabular text-muted-foreground">0{index + 1}</span>
                <Icon className="size-4 text-primary" />
                <h3 className="text-sm font-semibold">{title}</h3>
              </div>
              <p className="mt-3 text-xs font-medium text-primary">{location}</p>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">{body}</p>
              <p className="mt-3 flex items-center gap-2 text-xs">
                <ArrowRight className="size-3 text-muted-foreground" />
                {output}
              </p>
            </li>
          ))}
        </ol>
      </section>
      <section className="border-t border-border py-7">
        <h2 className="mb-5 text-lg font-semibold">What the security signals mean</h2>
        <dl className="grid gap-x-8 md:grid-cols-2">
          {glossary.map(([term, meaning]) => (
            <div key={term} className="border-b border-border/50 py-4">
              <dt className="text-sm font-semibold">{term}</dt>
              <dd className="mt-2 text-sm leading-6 text-muted-foreground">{meaning}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section className="border-t border-border py-7">
        <h2 className="mb-5 text-lg font-semibold">The dashboard, step by step</h2>
        <div className="space-y-5">
          {[
            {
              to: "/",
              title: "01 · Load and review",
              body: "Upload a scored vulnerability CSV on Overview. Header names are matched automatically. The four totals describe the entire file; secondary counts and charts reflect the active filters.",
            },
            {
              to: "/intelligence",
              title: "02 · Inspect individual findings",
              body: "Search by CVE or description, filter by priority, KEV membership or exposure, and sort the vulnerability table. Scores and priority labels remain those in the source file.",
            },
            {
              to: "/priority",
              title: "03 · Compare priorities across context",
              body: "Review score distribution, priority by internet exposure and priority by KEV status. A view is available only when its required columns are detected.",
            },
            {
              to: "/explainability",
              title: "04 · Review signal profiles",
              body: "Compare mean numeric values across exported priority tiers. These summaries describe the data; they are not feature importance, SHAP values or causal explanations of a prediction.",
            },
            {
              to: "/evaluation",
              title: "05 · Compare exported model results",
              body: "Upload a separate evaluation CSV: model names in the first column and metrics in the remaining columns. The dashboard displays results; it does not run evaluation. Green marks the largest numeric value, which is not necessarily best for error or timing metrics.",
            },
            {
              to: "/reports",
              title: "06 · Export the current selection",
              body: "Download filtered vulnerability records as CSV with every original column. The Reports page also lists detected fields and lets you remove the loaded dataset.",
            },
          ].map(({ to, title, body }) => (
            <div key={to} className="grid gap-2 md:grid-cols-[240px_1fr]">
              <Button
                asChild
                variant="link"
                className="h-auto justify-start whitespace-normal px-0 py-0 text-left"
              >
                <Link to={to}>
                  {title}
                  <ArrowRight />
                </Link>
              </Button>
              <p className="text-sm leading-6 text-muted-foreground">{body}</p>
            </div>
          ))}
        </div>
      </section>
      <section className="border-t border-border py-7">
        <h2 className="mb-4 text-lg font-semibold">Common questions</h2>
        <div className="divide-y divide-border">
          {[
            [
              "Where is my data saved?",
              "CSV parsing and result storage happen in this browser. Uploaded datasets and methodology notes are saved in browser storage, not a shared cloud account. Use Reports to remove vulnerability data and Comparative Evaluation to replace its file. Clearing browser site data also removes these saved files and notes.",
            ],
            [
              "Does a Critical label prove exploitation?",
              "No. Priority is the label in your exported results. KEV membership is a separate signal, and neither field demonstrates compromise of your own environment.",
            ],
            [
              "Why is a chart empty?",
              "The CSV may not contain a recognized column, numeric values, or records matching the current filters. Check the detected field names in Reports. The dashboard does not fill missing values with invented findings.",
            ],
            [
              "Which model and thresholds are used?",
              "The presentation names Scikit-learn and XGBoost but does not give a finalized model, training split, weights or thresholds. Add the actual methodology from your Python work to Comparative Evaluation; no formula is assumed here.",
            ],
            [
              "Are the presentation’s example scores real results?",
              "They are illustrative examples, not an uploaded research dataset. They are intentionally excluded from dashboard totals, charts and reports.",
            ],
            [
              "Is this the same as XBOW?",
              "No. XBOW was used as a reference for clearly organizing product information and the workflow. RiskRank-VAPT is a contextual prioritization research project; this dashboard does not provide autonomous penetration testing.",
            ],
          ].map(([question, answer]) => (
            <details key={question} className="group py-4">
              <summary className="cursor-pointer text-sm font-medium marker:text-muted-foreground">
                {question}
              </summary>
              <p className="mt-3 max-w-3xl pl-4 text-sm leading-6 text-muted-foreground">
                {answer}
              </p>
            </details>
          ))}
        </div>
      </section>
    </div>
  );
}
