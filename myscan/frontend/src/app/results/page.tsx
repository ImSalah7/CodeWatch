"use client";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ResultsClient } from "@/components/results/ResultsClient";

function ResultsPageInner() {
  const searchParams = useSearchParams();
  const initialJobId = searchParams.get("job_id") || "";
  return <ResultsClient key={initialJobId || "latest"} initialJobId={initialJobId} />;
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-zinc-400">Loading results...</div>}>
      <ResultsPageInner />
    </Suspense>
  );
}
