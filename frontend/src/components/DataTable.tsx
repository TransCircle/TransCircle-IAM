import * as React from "react";
import { EmptyState, Skeleton } from "./ui";
import { cn } from "@/lib/utils";

export interface Column<T> {
  header: string;
  cell: (row: T) => React.ReactNode;
  className?: string;
}

export function DataTable<T>({
  columns,
  rows,
  loading,
  empty = "暂无数据",
  rowKey,
  onRowClick,
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  loading?: boolean;
  empty?: string;
  rowKey: (row: T) => string;
  // When provided, rows become clickable (e.g. to open a detail page). Action
  // buttons inside a row should call e.stopPropagation() to avoid triggering it.
  onRowClick?: (row: T) => void;
}) {
  if (loading) {
    return (
      <div className="space-y-2 rounded-lg border bg-card p-4">
        <Skeleton className="h-8" />
        <Skeleton className="h-8 opacity-80" />
        <Skeleton className="h-8 opacity-60" />
        <Skeleton className="h-8 opacity-40" />
      </div>
    );
  }
  if (!rows || rows.length === 0) {
    return <EmptyState message={empty} />;
  }
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="tc-table w-full text-sm">
        <thead className="border-b bg-muted/60 text-left">
          <tr>
            {columns.map((c, i) => (
              <th key={i} className={cn("mono-label whitespace-nowrap px-4 py-2.5 text-muted-foreground", c.className)}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={
                onRowClick
                  ? (e) => {
                      if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(row);
                    }
                  : undefined
              }
              className={cn(
                "transition-colors hover:bg-accent/40",
                onRowClick && "cursor-pointer focus-visible:outline-none focus-visible:bg-accent/40"
              )}
            >
              {columns.map((c, i) => (
                <td key={i} data-label={c.header} className={cn("px-4 py-3 align-middle", c.className)}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
