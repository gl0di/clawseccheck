// Extracts numeric IDs from scraped HTML.
export function extractIds(html: string): string[] {
  const matches = html.match(/\d{12,}/g) || [];
  return matches.filter((m) => !/[^\d]/.test(m));
}
