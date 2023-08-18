use std::convert::TryInto;
use std::io::{Read, Error, Write};
use std::io::ErrorKind::WriteZero;

use gmime::StreamExtManual;
use gmime::traits::StreamExt;

pub struct Stream<'a>(pub &'a gmime::Stream);

impl<'a> Read for Stream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.0.read(buf);
        if size >= 0 {
            Ok(size.try_into().unwrap())
        } else {
            Err(Error::from_raw_os_error(size as i32))
        }
    }
}

impl<'a> Write for Stream<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let size = StreamExtManual::write(self.0, buf);
        if size > 0 {
            return Ok(size.try_into().unwrap())
        }
        Err(Error::from_raw_os_error(size as i32))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let size = self.0.flush();
        if size < 0 {
            Err(Error::from_raw_os_error(size as i32))
        } else {
            Ok(())
        }
    }
}
