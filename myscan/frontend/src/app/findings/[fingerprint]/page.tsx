import { FindingDetailClient } from "@/components/findings/FindingDetailClient";

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ fingerprint: string }>;
}) {
  const { fingerprint } = await params;
  return <FindingDetailClient fingerprint={fingerprint} />;
}
