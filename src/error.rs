error_chain! {
    errors {
        BuildPacketError
        ParsePacketError
        SendPacketError
    }

    foreign_links {
        IOError(::std::io::Error);
    }
}
