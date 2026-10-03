/**
 * Renders backend prose, turning `backtick` spans into <code>. Everything is rendered as React text,
 * so backend content can never inject markup.
 */
export function InlineText({ text }: { text: string }) {
  const parts = text.split(/`([^`]+)`/);
  return (
    <>
      {parts.map((part, index) =>
        index % 2 === 1 ? (
          <code key={index} className="inline-code">
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}
