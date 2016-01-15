inf = 100

map = [[inf, 7, 9, inf, inf, 14],
       [7, inf, 10, 15, inf, inf],
       [9, 10, inf, 11, inf, 2],
       [inf, 15, 11, inf, 5, inf],
       [inf, inf, inf, 5, inf, 9],
       [14, inf, 2, inf, 9, inf]]


def dijkstra(map, src, end):
    # init
    done = [src]  # finish point
    lenth = len(map)
    dis = {}  # record $dis from src
    pre = {src: None}  # record $pre path(last path)
    for i in range(lenth):
        dis[i] = map[src][i]
        if dis[i] < inf:
            pre[i] = src

    while end not in done:
        # chose the new point
        mindis = inf
        current = None  # init current
        for i in dis:
            if i not in done and dis[i] < mindis:
                current = i
                mindis = dis[i]
        done.append(current)
        # update $dis and $pre
        for i in dis:
            if i not in done and dis[i] > dis[current] + map[current][i]:
                dis[i] = dis[current] + map[current][i]
                pre[i] = current
    # output : path,dis
    path = []
    last=end
    while last!=src:
        path.append(last)
        last=pre[last]
    path.append(src)

    return path, dis[end]


path, dis = dijkstra(map, 0,4)
print path, dis
