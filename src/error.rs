error_chain! {
    errors {
        BuildPacketError
        ParsePacketError
        SendPacketError

        PingTimeout
    }

    foreign_links {
        IOError(::std::io::Error);
        SysTimeError(::std::time::SystemTimeError);
    }
}
