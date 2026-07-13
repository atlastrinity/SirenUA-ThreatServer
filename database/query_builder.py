from fastapi import HTTPException
from database.db_helpers import execute_query_as_dicts

def build_and_execute_query(
    base_query: str,
    date_column: str = "timestamp",
    days: int = None,
    filters: dict = None,
    order_by: str = None,
    limit: int = None,
    max_limit: int = 500,
    json_fields: list = None
) -> list:
    """
    Допоміжна функція для побудови та виконання SQL-запитів.
    Автоматично додає WHERE, параметри фільтрації, ORDER BY та LIMIT.
    Обробляє Exception та повертає HTTPException(500), усуваючи дублювання try/except.
    """
    try:
        query = base_query
        params = []
        has_where = "WHERE" in base_query.upper()

        if days is not None:
            clause = f"{date_column} >= datetime('now', ?)"
            if has_where:
                query += f" AND {clause}"
            else:
                query += f" WHERE {clause}"
                has_where = True
            params.append(f'-{days} days')

        if filters:
            for key, val in filters.items():
                if val is not None:
                    if has_where:
                        query += f" AND {key} = ?"
                    else:
                        query += f" WHERE {key} = ?"
                        has_where = True
                    params.append(val)

        if order_by:
            query += f" ORDER BY {order_by}"

        if limit is not None:
            query += " LIMIT ?"
            params.append(min(limit, max_limit))

        return execute_query_as_dicts(query, tuple(params), json_fields=json_fields)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
