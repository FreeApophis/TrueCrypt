/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004-2005
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

#include "TCdefs.h"
#include "redtick.h"

LRESULT CALLBACK
RedTick (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  if (uMsg == WM_CREATE)
    {
    }
  else if (uMsg == WM_DESTROY)
    {
    }
  else if (uMsg == WM_TIMER)
    {
    }
  else if (uMsg == WM_PAINT)
    {
      PAINTSTRUCT tmp;
      HPEN hPen;
      HDC hDC;
      BOOL bEndPaint;
      RECT Rect;

      if (GetUpdateRect (hwnd, NULL, FALSE))
	{
	  hDC = BeginPaint (hwnd, &tmp);
	  bEndPaint = TRUE;
	  if (hDC == NULL)
	    return DefWindowProc (hwnd, uMsg, wParam, lParam);
	}
      else
	{
	  hDC = GetDC (hwnd);
	  bEndPaint = FALSE;
	}

      GetClientRect (hwnd, &Rect);

      hPen = CreatePen (PS_SOLID, 2, RGB (0, 255, 0));
      if (hPen != NULL)
	{
	  HGDIOBJ hObj = SelectObject (hDC, hPen);
	  WORD bx = LOWORD (GetDialogBaseUnits ());
	  WORD by = HIWORD (GetDialogBaseUnits ());

	  MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);
	  LineTo (hDC, Rect.right, Rect.top);
	  MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);

	  LineTo (hDC, (3 * bx) / 4, (2 * by) / 8);

	  SelectObject (hDC, hObj);
	  DeleteObject (hPen);
	}

      if (bEndPaint == TRUE)
	EndPaint (hwnd, &tmp);
      else
	ReleaseDC (hwnd, hDC);

      return TRUE;
    }

  return DefWindowProc (hwnd, uMsg, wParam, lParam);
}

BOOL
RegisterRedTick (HINSTANCE hInstance)
{
  WNDCLASS wc;
  ULONG rc;

  memset(&wc, 0 , sizeof wc);

  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.cbClsExtra = 0;
  wc.cbWndExtra = 4;
  wc.hInstance = hInstance;
  wc.hIcon = LoadIcon (NULL, IDI_APPLICATION);
  wc.hCursor = NULL;
  wc.hbrBackground = GetStockObject (LTGRAY_BRUSH);
  wc.lpszClassName = "REDTICK";
  wc.lpfnWndProc = &RedTick; 
  
  rc = (ULONG) RegisterClass (&wc);

  return rc == 0 ? FALSE : TRUE;
}

BOOL
UnregisterRedTick (HINSTANCE hInstance)
{
  return UnregisterClass ("REDTICK", hInstance);
}
