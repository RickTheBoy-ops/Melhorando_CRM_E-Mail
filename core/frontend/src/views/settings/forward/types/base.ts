export type Forward = {
	address: string
	goto: string
	domain: string
	create_time: number
	update_time: number
	active: number
}

export type ForwardParams = {
	keyword: string
	domain: string
	page: number
	page_size: number
}
