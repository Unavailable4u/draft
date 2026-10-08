import ReactMarkdown from "react-markdown";

/** Model output is untrusted: react-markdown escapes raw HTML and strips unsafe URL schemes. */
export function Md({ children }: { children: string }) {
  return (
    <ReactMarkdown components={{
      p: ({ children }) => <p className="my-1 first:mt-0 last:mb-0">{children}</p>,
      ul: ({ children }) => <ul className="my-1 list-disc pl-5">{children}</ul>,
      ol: ({ children }) => <ol className="my-1 list-decimal pl-5">{children}</ol>,
      code: ({ children }) => <code className="rounded bg-zinc-800 px-1 py-0.5 text-[0.85em]">{children}</code>,
      pre: ({ children }) => (
        <pre className="my-1 overflow-x-auto rounded bg-zinc-950 p-2 text-xs [&_code]:bg-transparent [&_code]:p-0">{children}</pre>
      ),
      a: ({ href, children }) => (
        <a href={href} target="_blank" rel="noopener noreferrer" className="text-emerald-400 underline">{children}</a>
      ),
    }}>{children}</ReactMarkdown>
  );
}
