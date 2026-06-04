import * as React from "react";
import { EmptyState, Spinner } from "./ui";

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
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  loading?: boolean;
  empty?: string;
  rowKey: (row: T) => string;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center rounded-lg border p-10 text-muted-foreground">
        <Spinner className="h-5 w-5" />
      </div>
    );
  }
  if (!rows || rows.length === 0) {
    return <EmptyState message={empty} />;
  }
  return (
    <div className="overflow-hidden rounded-lg border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50 text-left text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            {columns.map((c, i) => (
              <th key={i} className={"px-4 py-3 font-medium " + (c.className || "")}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((row) => (
            <tr key={rowKey(row)} className="hover:bg-muted/30">
              {columns.map((c, i) => (
                <td key={i} className={"px-4 py-3 align-middle " + (c.className || "")}>
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
