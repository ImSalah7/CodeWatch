"use client";
import { Suspense } from "react";
import { ResultsClient } from "@/components/results/ResultsClient";

export default function ResultsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-zinc-400">Loading results...</div>}>
      <ResultsClient />
    </Suspense>
  );
}
