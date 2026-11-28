use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Language {
    #[default]
    Zh,
    En,
}

impl Language {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Zh => "中文",
            Self::En => "English",
        }
    }

    pub(super) fn app_title(self) -> &'static str {
        match self {
            Self::Zh => "A信 ASL",
            Self::En => "ASL",
        }
    }

    pub(super) fn page(self, page: super::views::Page) -> &'static str {
        match (self, page) {
            (Self::Zh, super::views::Page::Overview) => "概览",
            (Self::Zh, super::views::Page::Activity) => "活动",
            (Self::Zh, super::views::Page::Nodes) => "节点",
            (Self::Zh, super::views::Page::Contacts) => "联系人",
            (Self::Zh, super::views::Page::Groups) => "群组",
            (Self::Zh, super::views::Page::Transfers) => "传输",
            (Self::Zh, super::views::Page::Knowledge) => "资源与经验",
            (Self::Zh, super::views::Page::Trust) => "信任与贡献",
            (Self::Zh, super::views::Page::Access) => "授权",
            (Self::Zh, super::views::Page::Migration) => "迁移",
            (Self::En, super::views::Page::Overview) => "Overview",
            (Self::En, super::views::Page::Activity) => "Activity",
            (Self::En, super::views::Page::Nodes) => "Nodes",
            (Self::En, super::views::Page::Contacts) => "Contacts",
            (Self::En, super::views::Page::Groups) => "Groups",
            (Self::En, super::views::Page::Transfers) => "Transfers",
            (Self::En, super::views::Page::Knowledge) => "Resources",
            (Self::En, super::views::Page::Trust) => "Trust",
            (Self::En, super::views::Page::Access) => "Access",
            (Self::En, super::views::Page::Migration) => "Migration",
        }
    }

    pub(super) fn refresh(self) -> &'static str {
        match self {
            Self::Zh => "刷新",
            Self::En => "Refresh",
        }
    }

    pub(super) fn settings(self) -> &'static str {
        match self {
            Self::Zh => "设置",
            Self::En => "Settings",
        }
    }

    pub(super) fn quit(self) -> &'static str {
        match self {
            Self::Zh => "退出",
            Self::En => "Quit",
        }
    }

    pub(super) fn choose_language(self) -> &'static str {
        match self {
            Self::Zh => "选择语言",
            Self::En => "Choose language",
        }
    }
}
