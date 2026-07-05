export type FriendLink = {
    name: string;
    url: string;
    avatar: string;
    label?: string;
    description?: string;
    tags?: string[];
};

export const friendLinks: FriendLink[] = [
    {
        name: "きたがわまりん",
        url: "https://www.2rk.cc/detail/101vGqIbcE5sbJ1EQ0Ln?id=1",
        avatar: "/friend-avatars/kitagawa-marin.jpg",
        label: "❤",
        description: "喜多川海梦",
    },
    {
        name: "莱昂内尔·梅西",
        url: "https://www.instagram.com/leomessi/",
        avatar: "/friend-avatars/leomessi.jpg",
        label: "Instagram",
        description: "球王",
    },
    {
        name: "柳智敏",
        url: "https://www.instagram.com/katarinabluu/",
        avatar: "/friend-avatars/katarinabluu.jpg",
        label: "Instagram",
        description: "妈妈",
    },
    {
        name: "伊东纯也",
        url: "https://www.instagram.com/1409junya/",
        avatar: "/friend-avatars/1409junya.jpg",
        label: "Instagram",
        description: "日本国家队足球运动员",
    },
];
