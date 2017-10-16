error_chain! {
    errors {
        BuildPacketError
        ParsePacketError
        SendPacketError
        CreateChannelError

        PingTimeout
    }

    foreign_links {
        IOError(::std::io::Error);
        SysTimeError(::std::time::SystemTimeError);
    }
}
