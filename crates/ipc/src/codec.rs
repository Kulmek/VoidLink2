//! Кодек фреймов: `u32 LE длина | JSON`. Лимит — [`MAX_FRAME`].

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Максимальный размер тела фрейма — 1 МиБ.
pub const MAX_FRAME: usize = 1 << 20;

/// Ошибка чтения/записи фрейма. Любая из них, кроме `Io` с таймаутом, —
/// повод закрыть соединение.
#[derive(Debug)]
pub enum CodecError {
    /// Пир закрыл соединение ровно на границе фрейма.
    Closed,
    /// Соединение оборвалось посреди фрейма.
    Truncated,
    /// Длина 0 — пустой фрейм не бывает валидным JSON.
    BadLength,
    /// Длина больше [`MAX_FRAME`].
    TooLarge(usize),
    /// Тело не разбирается как ожидаемое сообщение.
    Json(serde_json::Error),
    /// Ошибка ввода-вывода.
    Io(io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Closed => write!(f, "соединение закрыто"),
            CodecError::Truncated => write!(f, "соединение оборвалось посреди фрейма"),
            CodecError::BadLength => write!(f, "неверная длина фрейма"),
            CodecError::TooLarge(n) => write!(f, "фрейм {n} байт больше лимита {MAX_FRAME}"),
            CodecError::Json(e) => write!(f, "неверный JSON: {e}"),
            CodecError::Io(e) => write!(f, "ошибка ввода-вывода: {e}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(e: io::Error) -> Self {
        CodecError::Io(e)
    }
}

/// Сериализует `msg` и пишет одним фреймом (заголовок и тело — одной записью).
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), CodecError> {
    let body = serde_json::to_vec(msg).map_err(CodecError::Json)?;
    if body.len() > MAX_FRAME {
        return Err(CodecError::TooLarge(body.len()));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Читает ровно `buf.len()` байт; `Ok(false)` — EOF до первого байта.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, CodecError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(CodecError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(CodecError::Io(e)),
        }
    }
    Ok(true)
}

/// Читает сырое тело фрейма. Длина проверяется до выделения памяти.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut hdr = [0u8; 4];
    if !read_full(r, &mut hdr)? {
        return Err(CodecError::Closed);
    }
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 {
        return Err(CodecError::BadLength);
    }
    if len > MAX_FRAME {
        return Err(CodecError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    if !read_full(r, &mut body)? {
        return Err(CodecError::Truncated);
    }
    Ok(body)
}

/// Читает и разбирает одно сообщение.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, CodecError> {
    let body = read_frame(r)?;
    serde_json::from_slice(&body).map_err(CodecError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ClientKind, ClientMsg};
    use std::io::Cursor;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn roundtrip_in_memory() {
        let mut buf = Vec::new();
        let m = ClientMsg::hello(ClientKind::Cli, "1");
        write_msg(&mut buf, &m).unwrap();
        write_msg(&mut buf, &ClientMsg::Bye).unwrap();
        let mut c = Cursor::new(buf);
        assert_eq!(read_msg::<_, ClientMsg>(&mut c).unwrap(), m);
        assert_eq!(read_msg::<_, ClientMsg>(&mut c).unwrap(), ClientMsg::Bye);
        assert!(matches!(
            read_msg::<_, ClientMsg>(&mut c),
            Err(CodecError::Closed)
        ));
    }

    #[test]
    fn bad_inputs() {
        let r = |b: Vec<u8>| read_msg::<_, ClientMsg>(&mut Cursor::new(b));
        assert!(matches!(r(vec![0, 0, 0, 0]), Err(CodecError::BadLength)));
        assert!(matches!(r(vec![1, 0]), Err(CodecError::Truncated)));
        assert!(matches!(
            r(((MAX_FRAME + 1) as u32).to_le_bytes().to_vec()),
            Err(CodecError::TooLarge(_))
        ));
        assert!(matches!(
            r(u32::MAX.to_le_bytes().to_vec()),
            Err(CodecError::TooLarge(_))
        ));
        let mut t = frame(b"{\"t\":\"bye\"}");
        t.truncate(8);
        assert!(matches!(r(t), Err(CodecError::Truncated)));
        assert!(matches!(
            r(frame(b"\xff\x00garbage")),
            Err(CodecError::Json(_))
        ));
        assert!(matches!(
            r(frame(b"{\"t\":\"nope\"}")),
            Err(CodecError::Json(_))
        ));
    }

    #[test]
    fn exactly_max_frame_is_accepted() {
        // Тело ровно MAX_FRAME байт: строка JSON в кавычках.
        let mut body = vec![b'"'];
        body.extend(std::iter::repeat_n(b'x', MAX_FRAME - 2));
        body.push(b'"');
        let v: String = read_msg(&mut Cursor::new(frame(&body))).unwrap();
        assert_eq!(v.len(), MAX_FRAME - 2);
    }

    #[test]
    fn write_rejects_oversize() {
        let big = ClientMsg::Req {
            id: 1,
            cmd: serde_json::Value::String("x".repeat(MAX_FRAME)),
        };
        let mut buf = Vec::new();
        assert!(matches!(
            write_msg(&mut buf, &big),
            Err(CodecError::TooLarge(_))
        ));
        assert!(buf.is_empty());
    }
}
