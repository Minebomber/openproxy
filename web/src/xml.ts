export function formatXml(text: string): string {
  if (text.length > 4 * 1024 * 1024) throw new Error('XML preview exceeds 4 MiB');
  if (/<!\s*(DOCTYPE|ENTITY)\b/i.test(text))
    throw new Error('XML DTD/entity declarations are not supported in previews');
  const document = new DOMParser().parseFromString(text, 'application/xml');
  const error =
    document.getElementsByTagNameNS(
      'http://www.mozilla.org/newlayout/xml/parsererror.xml',
      'parsererror',
    )[0] || document.getElementsByTagNameNS('http://www.w3.org/1999/xhtml', 'parsererror')[0];
  if (error) throw new Error(`Invalid XML: ${error.textContent?.slice(0, 500)}`);
  const serializer = new XMLSerializer(),
    lines: string[] = [],
    budget = { nodes: 20000, bytes: 0 };
  function append(value: string) {
    budget.bytes += value.length;
    if (budget.bytes > 4 * 1024 * 1024) throw new Error('Formatted XML exceeds 4 MiB');
    lines.push(value);
  }
  function node(value: Node, depth: number) {
    if (--budget.nodes < 0 || depth > 64) throw new Error('XML preview exceeds node/depth limit');
    const indent = '  '.repeat(depth);
    if (value.nodeType !== Node.ELEMENT_NODE) {
      if (value.nodeType !== Node.TEXT_NODE || value.textContent?.trim())
        append(indent + serializer.serializeToString(value));
      return;
    }
    const element = value as Element,
      children = [...element.childNodes];
    if (
      children.some(
        (child) =>
          child.nodeType === Node.CDATA_SECTION_NODE ||
          (child.nodeType === Node.TEXT_NODE && !!child.textContent?.trim()),
      ) ||
      element.getAttribute('xml:space') === 'preserve' ||
      !children.length
    ) {
      append(indent + serializer.serializeToString(element));
      return;
    }
    const clone = element.cloneNode(false) as Element,
      opening = serializer.serializeToString(clone).replace(/\s*\/>$/, '>');
    append(indent + opening);
    for (const child of children) node(child, depth + 1);
    append(indent + `</${element.tagName}>`);
  }
  for (const child of document.childNodes) node(child, 0);
  return lines.join('\n');
}
