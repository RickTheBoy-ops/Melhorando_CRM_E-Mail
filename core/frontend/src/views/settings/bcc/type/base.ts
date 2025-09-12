export type Bcc = {
	id: number
	type: string
	address: string
	goto: string
	domain: string
	create_time: number
	update_time: number
	active: number
}

export type BccParams = {
	keyword: string
	domain: string
	page: number
	page_size: number
}
