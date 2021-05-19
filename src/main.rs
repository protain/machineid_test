#![windows_subsystem = "windows"]

use anyhow::{anyhow, Result};
use std::{fmt::Write, mem, usize};
use std::{mem::size_of, ptr};
use winapi::{
    ctypes::{c_char, c_void},
    shared::{
        minwindef::{BYTE, DWORD, WORD},
        ntdef::BOOLEAN,
    },
    um::{
        fileapi::{self, OPEN_EXISTING},
        handleapi::CloseHandle,
        ioapiset::DeviceIoControl,
        sysinfoapi::GetSystemFirmwareTable,
        winioctl::{IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE},
    },
};

fn encode(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct STORAGE_DESCRIPTOR_HEADER {
    Version: DWORD,
    Size: DWORD,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct STORAGE_DEVICE_DESCRIPTOR {
    Version: DWORD,
    Size: DWORD,
    DeviceType: BYTE,
    DeviceTypeModifier: BYTE,
    RemovableMedia: BOOLEAN,
    CommandQueueing: BOOLEAN,
    VendorIdOffset: DWORD,
    ProductIdOffset: DWORD,
    ProductRevisionOffset: DWORD,
    SerialNumberOffset: DWORD,
    BusType: u32, //STORAGE_BUS_TYPE,
    RawPropertiesLength: DWORD,
    RawDeviceProperties: *mut BYTE,
}

fn get_drive_serialno() -> Result<String> {
    unsafe {
        let device_handle = fileapi::CreateFileW(
            encode("\\\\.\\PhysicalDrive0").as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        if device_handle as i32 == -1 {
            return Err(anyhow!("invalid handle value. value = {:?}", device_handle));
        }
        let mut storage_property_query = mem::zeroed::<STORAGE_PROPERTY_QUERY>();
        let mut storage_desc_header = mem::zeroed::<STORAGE_DESCRIPTOR_HEADER>();
        let mut bytes: DWORD = 0;

        let storage_ptr = (&mut storage_property_query) as *mut STORAGE_PROPERTY_QUERY;
        let desc_ptr = (&mut storage_desc_header) as *mut STORAGE_DESCRIPTOR_HEADER;

        let _ = DeviceIoControl(
            device_handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            storage_ptr as *mut c_void,
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            desc_ptr as *mut c_void,
            size_of::<STORAGE_DESCRIPTOR_HEADER>() as u32,
            &mut bytes,
            ptr::null_mut(),
        );

        let bufsize = storage_desc_header.Size;
        let mut outbuff = Vec::<u8>::with_capacity(bufsize as usize);

        let _ = DeviceIoControl(
            device_handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            storage_ptr as *mut c_void,
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            outbuff.as_mut_ptr() as *mut c_void,
            bufsize,
            &mut bytes,
            ptr::null_mut(),
        );

        let dev_desc = mem::transmute::<*mut u8, &STORAGE_DEVICE_DESCRIPTOR>(outbuff.as_mut_ptr());

        let serial_name = std::ffi::CStr::from_ptr(
            (outbuff.as_mut_ptr() as usize + dev_desc.SerialNumberOffset as usize) as *mut c_char,
        );

        let _ = CloseHandle(device_handle);
        Ok(serial_name.to_str()?.to_string())
    }
}

/*
  SMBIOS Structure header as described at
  https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf
  (para 6.1.2)
*/
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct DMIHeader {
    Type: BYTE,
    Length: BYTE,
    Handle: WORD,
    Data: BYTE,
}

/*
  Structure needed to get the SMBIOS table using GetSystemFirmwareTable API.
  see https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
*/
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case, non_camel_case_types)]
struct RawSMBIOSData {
    Used20CallingMethod: BYTE,
    SMBIOSMajorVersion: BYTE,
    SMBIOSMinorVersion: BYTE,
    DmiRevision: BYTE,
    Length: DWORD,
    SMBIOSTableData: BYTE,
}

fn get_biosuuid() -> Result<String> {
    unsafe {
        let size: DWORD = 0;

        let rsmb = std::mem::transmute::<[u8; 4], u32>([b'R', b'S', b'M', b'B']).to_be();
        let size = GetSystemFirmwareTable(rsmb, 0, ptr::null_mut(), size);
        if size == 0 {
            return Err(anyhow!("GetSystemFirmwareTable failed."));
        }

        let mut smb_buff = Vec::<u8>::with_capacity(size as usize);

        let _ = GetSystemFirmwareTable(rsmb, 0, smb_buff.as_mut_ptr() as *mut c_void, size);

        let smb_bios_data = mem::transmute::<*mut u8, &mut RawSMBIOSData>(smb_buff.as_mut_ptr());
        let mut data = (&mut smb_bios_data.SMBIOSTableData) as *mut u8;

        let tbl_dat_ptr = (&mut smb_bios_data.SMBIOSTableData) as *mut u8;
        let mut vres = Vec::<u8>::new();
        while data < tbl_dat_ptr.offset(smb_bios_data.Length as isize) {
            let h = mem::transmute::<*mut u8, &DMIHeader>(data);

            if h.Length < 4 {
                break;
            }

            if h.Type == 0x01 && h.Length >= 0x19 {
                data = data.offset(0x08);

                let mut all_zero = true;
                let mut all_one = true;
                for i in 0..16 {
                    if !all_zero && !all_one {
                        break;
                    }
                    if *data.offset(i as isize) != 0x00 {
                        all_zero = false;
                    }
                    if *data.offset(i as isize) != 0xff {
                        all_one = false;
                    }
                }
                if !all_zero && !all_one {
                    vres.push(*data.offset(3));
                    vres.push(*data.offset(2));
                    vres.push(*data.offset(1));
                    vres.push(*data.offset(0));
                    vres.push(*data.offset(5));
                    vres.push(*data.offset(4));
                    vres.push(*data.offset(7));
                    vres.push(*data.offset(6));
                }
                for i in 8..16 {
                    vres.push(*data.offset(i));
                }
                break;
            }

            let mut next = data.offset(h.Length as isize);

            while next < tbl_dat_ptr.offset(smb_bios_data.Length as isize)
                && (*next != 0 || *next.offset(1) != 0)
            {
                next = next.offset(1);
            }
            next = next.offset(2);
            data = next;
        }
        let mut s = String::with_capacity(vres.len() * 2);
        for &b in vres.as_slice() {
            write!(&mut s, "{:02X}", b)?;
        }
        Ok(s)
    }
}

fn try_main() -> anyhow::Result<()> {
    let serino = get_drive_serialno().unwrap_or("UNKNOWN-SERINO".into());
    let biosid = get_biosuuid().unwrap_or("UNKNOWN-BIOSID".into());
    print!("Hello, world!, serino: {}, biosid: {}", serino, biosid);

    Ok(())
}

pub fn main() {
    match try_main() {
        Ok(_) => println!("OKOK"),
        Err(_) => println!("NGNG"),
    }
}
