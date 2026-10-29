import ReactMarkdown from "react-markdown";

/** Model output is untrusted: react-markdown escapes raw HTML and strips unsafe URL schemes. */
export function Md({ children }: { children: string }) {
  return (
    <ReactMarkdown components={{
      p: ({ children }) => <p className="my-1.5 first:mt-0 last:mb-0">{children}</p>,
      h1: ({ children }) => <h4 className="mb-1 mt-3 text-[1.1rem] font-bold first:mt-0">{children}</h4>,
      h2: ({ children }) => <h4 className="mb-1 mt-3 text-[1.05rem] font-bold first:mt-0">{children}</h4>,
      h3: ({ children }) => <h5 className="mb-1 mt-2 font-bold italic first:mt-0">{children}</h5>,
      strong: ({ children }) => <strong className="font-bold">{children}</strong>,
      ul: ({ children }) => <ul className="my-1.5 list-disc pl-5 marker:text-ink-3">{children}</ul>,
      ol: ({ children }) => <ol className="my-1.5 list-decimal pl-5 marker:text-ink-3">{children}</ol>,
      blockquote: ({ children }) => <blockquote className="my-1.5 border-l-2 border-rule pl-3 italic text-ink-2">{children}</blockquote>,
      code: ({ children }) => <code className="rounded-[4px] border border-rule bg-sunken px-1 py-px font-mono text-[0.84em]">{children}</code>,
      pre: ({ children }) => (
        <pre className="my-1.5 overflow-x-auto rounded-[5px] border border-rule bg-sunken p-2.5 font-mono text-[0.82rem] leading-relaxed [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0">{children}</pre>
      ),
      a: ({ href, children }) => (
        <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent-ink underline decoration-accent/40 underline-offset-2 hover:decoration-accent">{children}</a>
      ),
    }}>{children}</ReactMarkdown>
  );
}
