import { Link } from "@tanstack/react-router";
import { ArrowRight, BookOpen, Workflow } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ProjectSummary() {
  return (
    <section className="mb-6 border-b border-border pb-6">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span>Research project</span>
        <span aria-hidden="true">/</span>
        <span>GLA University · B.C.A. 2025–26</span>
      </div>
      <h2 className="mt-3 text-2xl font-semibold">RiskRank-VAPT</h2>
      <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
        Context-aware vulnerability prioritization. The proposed research combines vulnerability
        severity, exploit information, known exploitation and asset context to help decide what
        needs attention first.
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button asChild variant="outline" size="sm">
          <Link to="/how-it-works">
            <Workflow />
            How it works
            <ArrowRight />
          </Link>
        </Button>
        <Button asChild variant="ghost" size="sm">
          <Link to="/project">
            <BookOpen />
            Project details
          </Link>
        </Button>
      </div>
    </section>
  );
}
