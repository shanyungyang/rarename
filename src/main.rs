use std::io::*;
use std::fs;
use std::fs::File;
use std::vec::Vec;
use std::env;
use std::borrow::BorrowMut;
use std::char;
use std::path::{Path, PathBuf};

// const LHD_DIRECTORY : u16 = 0x00e0;
const LHD_LARGE : u16 = 0x0100;
// const LHD_UNICODE : u16 = 0x0200;

struct MemReader {
	buffer : Vec<u8>,
	cursor : usize,
}

impl MemReader {
	fn new(input: &mut Read, size: usize) -> Result<MemReader>
	{
		let mut buf = vec![0; size];
		try!(input.read(buf.borrow_mut()));

		return Ok(MemReader {
			buffer : buf,
			cursor : 0
		});
	}

	fn get1(&mut self) -> u8
	{
		let ret = self.buffer[self.cursor];
		self.cursor += 1;
		return ret;
	}

	fn get2(&mut self) -> u16
	{
		let (b, c) = (&self.buffer, self.cursor);
		let (b0, b1) = (b[c] as u16, b[c+1] as u16);
		self.cursor += 2;
		return b0 + (b1<<8);
	}

	fn get4(&mut self) -> u32
	{
		let (b, c) = (&self.buffer, self.cursor);
		let (b0, b1) = (b[c] as u32, b[c+1] as u32);
		let (b2, b3) = (b[c+2] as u32, b[c+3] as u32);
		self.cursor += 4;
		return b0 + (b1<<8) + (b2<<16) + (b3<<24);
	}

	fn get_names(&mut self, total_size: usize) -> (&[u8], &[u8])
	{
		let begin = self.cursor;
		while self.buffer[self.cursor] != 0 {
			self.cursor += 1;
		}
		self.cursor += 1;
		let name1 = &self.buffer[begin .. self.cursor];
		let size = total_size - name1.len();
		let name2 = &self.buffer[self.cursor .. self.cursor + size];
		self.cursor += size;
		return (name1, name2);
	}
}

fn main()
{
	for file in env::args().skip(1) {
		// split path first
		let src_path = Path::new(&file);
		let parent = src_path.parent();

		let dir_name = 
			if let Ok(input) = File::open(&file) {
				read_rar_file(input).unwrap_or_else(|e| {
					println!("error reading RAR archive: {}", e);
					None
				})
			}else{
				println!("error opening file {}", file);
				None
			};

		if let Some(dst_name) = dir_name {
			let mut dst_path = 
				if let Some(parent_dir) = parent {
					parent_dir.to_path_buf()
				}else{
					PathBuf::new()
				};

            // PathBuf::set_extension() will give wrong filename if dst_name contains a dot, so we append ".rar" to it directly.
			dst_path.push(dst_name + ".rar");

			if src_path != dst_path.as_path() {
				// println!("{} -> {}", src_path.to_string_lossy(), dst_path.as_path().to_string_lossy());
				if let Err(e) = fs::rename(src_path, dst_path) {
					println!("error rename file: {}", e);
				}
			}
		}
	}
}

fn read_rar_file(mut input : File) -> Result<Option<String>>
{
	let mut signature = [0; 7];
	try!(input.read(&mut signature));

	if signature != [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
		println!("input is not an RAR archive!");
		return Ok(None);
	}

	let mut dirs = Vec::new();
	// iterate all headers
	loop {
		// common header fields occupy 7 bytes
		let mut hd = try!(MemReader::new(&mut input, 7));


		let _ = hd.get2();
		let header_type = hd.get1();
		let header_flags = hd.get2();
		let header_size = hd.get2();

		// println!("header: 0x{:x}", header_type);

		match header_type {
			0x74 => {
				if let Some(dir_name) = try!(parse_file_header(&mut input, header_flags, header_size)) {
					dirs.push(dir_name);
				}
			},
			0x7a => {
				let _ = parse_service_header(&mut input, header_size);
			},
			0x7b => {
				// ENDARC
				break;
			},
			other if other <= 0x7b && other >= 0x72 => {
				let _ = parse_other_header(&mut input, header_size);
			},
			_ => {
				let pos = try!(input.seek(SeekFrom::Current(0)));
				println!("error: unknown header type at 0x{:x}", pos);
				return Ok(None);
			},
		}
	}
	if dirs.len() == 1 {
		return Ok(dirs.pop());
	}

	return Ok(None);
}

fn parse_other_header(input: &mut Seek, size: u16) -> Result<()>
{
	try!(input.seek(SeekFrom::Current( (size as i64) - 7 )));
	return Ok(());
}

fn parse_service_header(input: &mut File, header_size: u16) -> Result<()>
{
	let mut hd = try!(MemReader::new(input, (header_size as usize)-7));
	let skip_size = hd.get4() as i64;
	try!(input.seek(SeekFrom::Current(skip_size)));
	return Ok(());
}

fn parse_file_header(input: &mut File, flags: u16, header_size: u16) -> Result<Option<String>>
{
	// PackSize                4 bytes
	// UnpSize                 4 bytes
	// HostOS                  1 byte
	// FileCRC                 4 bytes
	// FileTime                4 bytes
	// UnpVer                  1 byte
	// Method                  1 byte
	// NameSize                2 bytes
	// FileAttr                4 bytes
	// HighPackSize            4 bytes (only present if LHD_LARGE is set)
	// HighUnpSize             4 bytes (only present if LHD_LARGE is set)
	// FileName                (NameSize) bytes
	// Salt                    8 bytes (only present if LHD_SALT is set)
	// ExtTime Structure       See Description (only present if LHD_EXTTIME is set)
	// Packed Data             (Total Packed Size) bytes

	let mut hd = try!(MemReader::new(input, (header_size as usize)-7));

	let mut skip_size = hd.get4() as i64;

	hd.get4(); // UnpSize
	hd.get1(); // HostOS
	hd.get4(); // FileCRC
	hd.get4(); // FileTime
	hd.get1(); // UnpVer
	hd.get1(); // Method

	let name_size = hd.get2() as usize;
	let file_attr = hd.get4();

	if flags & LHD_LARGE != 0 {
		let high_pack_size = hd.get4() as i64;
		skip_size += high_pack_size * 4294967296;
	}

	try!(input.seek(SeekFrom::Current(skip_size)));

	if file_attr == 0x10 {
		// println!("Get names, name_size = {}", name_size);
		let (name, enc_name) = hd.get_names(name_size);

		let dir_name = decode_name(name, enc_name);
		// println!("name_size = {}", name_size);
		// println!("name.len() = {}, enc_name.len() = {}", name.len(), enc_name.len());
		// println!("{}", dir_name);
		if dir_name.contains("\\") {
			return Ok(None);
		}else{
			return Ok(Some(dir_name));
		}
	}

	return Ok(None);
}


fn decode_name(name: &[u8], enc_name: &[u8]) -> String
{
	let mut flags : u8 =0;
  	let mut flag_bits : u32 =0;
	// let mut FlagsPos : usize =0;
	// let mut DestSize : usize =0;

	let mut enc_pos : usize = 0;
	let mut dec_pos : usize = 0;

  	// byte HighByte=EncName[EncPos++];
	let high_byte  = enc_name[enc_pos] as u32;
	enc_pos += 1;
	
	let mut name_w = String::new();
	// while (EncPos<EncSize && DecPos<MaxDecSize)
	// {
	while enc_pos < enc_name.len() {
		// if (FlagBits==0)
		// {
		//   Flags=EncName[EncPos++];
		//   FlagBits=8;
		// }
		if flag_bits == 0 {
			flags = enc_name[enc_pos];
			enc_pos += 1;
			flag_bits = 8;
		}
		// switch(Flags>>6)
		// {
		match flags>>6 {
			0 => {
				name_w.push(char::from_u32(enc_name[enc_pos] as u32).unwrap());
				enc_pos += 1;
				dec_pos += 1;
			},

			1 => {
				let ch = (enc_name[enc_pos] as u32) + (high_byte << 8);
				enc_pos += 1;
				name_w.push(char::from_u32(ch).unwrap());
				dec_pos += 1;
			},

			2 => {
				let ch = (enc_name[enc_pos] as u32) + ((enc_name[enc_pos+1] as u32) << 8);
				enc_pos += 2;
				name_w.push(char::from_u32(ch).unwrap());
				dec_pos += 1;
			},

			3 => {
				let mut length = enc_name[enc_pos] as isize;
				enc_pos += 1;
				if length & 0x80 != 0 {
					let correction = enc_name[enc_pos] as u32;
					enc_pos += 1;
					length = length & 0x7f;
					while length > 0 {
						let ch = (correction + (name[dec_pos] as u32)) & 0xff + (high_byte << 8);
						name_w.push(char::from_u32(ch).unwrap());

						length -= 1;
						dec_pos += 1;
					}
				}else{
					length += 2;
					while length > 0 {
						name_w.push(char::from_u32(name[dec_pos] as u32).unwrap());

						length -= 1;
						dec_pos += 1;
					}
				}
			},
			_ => panic!("name decode error"),
		}
		//   case 0:
		//     NameW[DecPos++]=EncName[EncPos++];
		//     break;
		//   case 1:
		//     NameW[DecPos++]=EncName[EncPos++]+(HighByte<<8);
		//     break;
		//   case 2:
		//     NameW[DecPos++]=EncName[EncPos]+(EncName[EncPos+1]<<8);
		//     EncPos+=2;
		//     break;
		//   case 3:
		//     {
		//       int Length=EncName[EncPos++];
		//       if (Length & 0x80)
		//       {
		//         byte Correction=EncName[EncPos++];
		//         for (Length=(Length&0x7f)+2;Length>0 && DecPos<MaxDecSize;Length--,DecPos++)
		//           NameW[DecPos]=((Name[DecPos]+Correction)&0xff)+(HighByte<<8);
		//       }
		//       else
		//         for (Length+=2;Length>0 && DecPos<MaxDecSize;Length--,DecPos++)
		//           NameW[DecPos]=Name[DecPos];
		//     }
		//     break;
		// }

		flags <<= 2;
		flag_bits -= 2;
	//   Flags<<=2;
	//   FlagBits-=2;
	// }
	}
	return name_w;
	// NameW[DecPos<MaxDecSize ? DecPos:MaxDecSize-1]=0;
}
