import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, ExternalLink, FileText, Target, Layers, GraduationCap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageTitle } from "@/components/rr/shell";
import presentation from "@/assets/riskrank-presentation.asset.json";

export const Route = createFileRoute("/project")({
  head: () => ({
    meta: [
      { title: "Project details · RiskRank-VAPT" },
      {
        name: "description",
        content:
          "RiskRank-VAPT research background, objectives, scope, technologies, team and references from the project presentation.",
      },
      { property: "og:title", content: "Project details · RiskRank-VAPT" },
      {
        property: "og:description",
        content:
          "A context-aware approach to vulnerability prioritization, presented by the GLA University project team.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Project,
});

const references = [
  [
    "National Vulnerability Database",
    "CVE records and vulnerability information",
    "https://nvd.nist.gov/",
  ],
  ["FIRST · CVSS", "Common Vulnerability Scoring System", "https://www.first.org/cvss/"],
  ["FIRST · EPSS", "Exploit Prediction Scoring System", "https://www.first.org/epss/"],
  [
    "CISA KEV",
    "Known Exploited Vulnerabilities catalog",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  ],
  ["Scikit-learn", "Machine learning documentation", "https://scikit-learn.org/"],
  ["XGBoost", "Gradient boosting documentation", "https://xgboost.readthedocs.io/"],
  ["OWASP", "Application security resources", "https://owasp.org/"],
];
const team = [
  ["Rohitash", "2442010471"],
  ["Sanjeet", "2442010492"],
  ["Satya", "2442010497"],
  ["Saurav", "2442010502"],
  ["Sujal Solanki", "2442010541"],
  ["Sumit Chauhan", "2442010544"],
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-border py-7">
      <h2 className="mb-4 text-lg font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Project() {
  return (
    <div className="max-w-5xl">
      <PageTitle
        title="Project details"
        action={
          <Button asChild variant="outline" size="sm">
            <a href={presentation.url} target="_blank" rel="noreferrer">
              <FileText />
              Original presentation
              <ExternalLink />
            </a>
          </Button>
        }
      />
      <section className="pb-7">
        <p className="text-xs text-primary">GLA University, Mathura · B.C.A. · Session 2025–26</p>
        <h2 className="mt-3 text-3xl font-semibold">RiskRank-VAPT</h2>
        <p className="mt-2 text-lg">Dynamic Vulnerability Prioritization Using Machine Learning</p>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-muted-foreground">
          Vulnerability scanners can identify many security issues, but severity alone does not show
          which finding is most urgent in a particular environment. RiskRank-VAPT proposes adding
          contextual security information and machine learning to produce a practical risk score and
          priority ranking.
        </p>
        <Button asChild size="sm" variant="link" className="mt-3 px-0">
          <Link to="/how-it-works">
            Explore the system workflow
            <ArrowRight />
          </Link>
        </Button>
      </section>
      <Section title="The problem">
        <div className="grid gap-6 md:grid-cols-2">
          <div>
            <h3 className="font-medium">Severity is not the same as urgency</h3>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Traditional CVSS-based ranking can assign similar priorities to vulnerabilities with
              very different real-world risks. Large finding lists make it difficult to decide what
              to fix first.
            </p>
          </div>
          <div className="border-l-2 border-primary pl-5">
            <h3 className="font-medium">The research question</h3>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              How can machine learning and contextual security information prioritize
              vulnerabilities according to their practical risk?
            </p>
          </div>
        </div>
      </Section>
      <Section title="Objectives and purpose">
        <div className="grid gap-6 md:grid-cols-3">
          {[
            {
              icon: Layers,
              title: "Collect and enrich",
              body: "Collect findings from a controlled testing environment; gather CVSS, exploit availability, KEV status and asset context.",
            },
            {
              icon: Target,
              title: "Score and prioritize",
              body: "Develop a machine learning model, assign a risk score and priority level, and order vulnerabilities for review.",
            },
            {
              icon: GraduationCap,
              title: "Explain and evaluate",
              body: "Provide understandable context, reduce alert fatigue, and compare the proposed ranking with conventional CVSS-based prioritization.",
            },
          ].map(({ icon: Icon, title, body }) => (
            <div key={title}>
              <Icon className="mb-3 size-5 text-primary" />
              <h3 className="text-sm font-semibold">{title}</h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">{body}</p>
            </div>
          ))}
        </div>
      </Section>
      <Section title="Scope and expected outcomes">
        <div className="grid gap-6 md:grid-cols-2">
          <div>
            <h3 className="text-sm font-semibold">Research scope</h3>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-muted-foreground">
              <li>Vulnerability collection and enrichment</li>
              <li>Feature extraction and ML-based risk prediction</li>
              <li>Priority ranking and contextual visualization</li>
              <li>Performance comparison with CVSS-based ranking</li>
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold">Expected outcomes, not measured results</h3>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">
              A risk score and priority level for each vulnerability, important findings placed
              first, and context behind the ranking. Effectiveness must be demonstrated using
              exported evaluation results; the presentation does not establish measured accuracy or
              improvement.
            </p>
          </div>
        </div>
      </Section>
      <Section title="Tools and requirements">
        <div className="grid gap-6 md:grid-cols-2">
          <dl className="space-y-4 text-sm">
            {[
              ["Programming and data", "Python, Pandas and NumPy"],
              ["Machine learning", "Scikit-learn and XGBoost"],
              ["Security information", "CVE / NVD, CISA KEV and exploit information"],
              [
                "Testing",
                "A controlled vulnerability-testing environment; one scanner for the initial implementation",
              ],
              ["Proposed output", "Dashboard and HTML or PDF report"],
            ].map(([name, value]) => (
              <div key={name}>
                <dt className="font-medium">{name}</dt>
                <dd className="mt-1 leading-6 text-muted-foreground">{value}</dd>
              </div>
            ))}
          </dl>
          <div>
            <h3 className="text-sm font-semibold">Research environment requirements</h3>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-muted-foreground">
              <li>Laptop or desktop with minimum 8 GB RAM</li>
              <li>Dual / quad core processor and sufficient storage</li>
              <li>Windows or Linux, Python and data / ML libraries</li>
              <li>Vulnerability scanning environment and data storage</li>
              <li>Web browser for the dashboard and reports</li>
            </ul>
            <p className="mt-4 text-xs leading-5 text-muted-foreground">
              These are the presentation’s research requirements, not minimum requirements to view
              this web dashboard. Current result downloads are CSV; HTML / PDF reporting is
              proposed.
            </p>
          </div>
        </div>
      </Section>
      <Section title="Future scope">
        <p className="text-sm leading-7 text-muted-foreground">
          Support for multiple scanners, improved false-positive detection, larger datasets,
          additional intelligence sources and cloud-based deployment are future directions in the
          presentation. They are not enabled by this dashboard.
        </p>
      </Section>
      <Section title="Project team">
        <div className="grid gap-6 md:grid-cols-2">
          <div>
            <h3 className="text-sm font-semibold">Under the supervision of</h3>
            <p className="mt-3 font-medium">Dr. Arun Singh Yadav</p>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">
              Assistant Professor
              <br />
              Department of Computer Engineering &amp; Applications
              <br />
              GLA University, Mathura
            </p>
          </div>
          <table className="w-full text-sm">
            <caption className="mb-3 text-left font-semibold">Presented by</caption>
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="pb-2 font-medium">Name</th>
                <th className="pb-2 font-medium">University roll no.</th>
              </tr>
            </thead>
            <tbody>
              {team.map(([name, roll]) => (
                <tr key={roll} className="border-b border-border/50">
                  <td className="py-2">{name}</td>
                  <td className="py-2 tabular text-muted-foreground">{roll}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
      <Section title="References">
        <div className="grid gap-x-8 md:grid-cols-2">
          {references.map(([name, description, url]) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noreferrer"
              className="flex items-start justify-between gap-3 border-b border-border/50 py-3 hover:text-primary"
            >
              <div>
                <span className="text-sm font-medium">{name}</span>
                <p className="mt-1 text-xs text-muted-foreground">{description}</p>
              </div>
              <ExternalLink className="mt-1 size-3.5 shrink-0 text-muted-foreground" />
            </a>
          ))}
        </div>
        <p className="mt-5 text-xs leading-6 text-muted-foreground">
          Content source: your RiskRank-VAPT presentation, including its reference to the Project
          Research Proposal (not supplied separately). XBOW informed the clear product and workflow
          structure only; its autonomous testing capabilities and performance claims do not apply to
          RiskRank-VAPT.
        </p>
      </Section>
    </div>
  );
}
