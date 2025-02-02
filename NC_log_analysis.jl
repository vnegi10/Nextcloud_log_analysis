### A Pluto.jl notebook ###
# v0.20.3

using Markdown
using InteractiveUtils

# ╔═╡ f87b8466-dc05-11ef-2c7f-6585551df9a1
using JSON, DataFrames, Dates

# ╔═╡ 4d81e853-e592-40c0-a66a-f5fa11467fe9
md"""
### Read input
"""

# ╔═╡ 15e06b0a-13de-4d70-99aa-f870b3b07732
begin
	fname_1 = "/home/vikas/Desktop/Nextcloud/nextcloud.log"
	fname_2 = "/home/vikas/Desktop/Nextcloud/nextcloud_web_download.log"
end

# ╔═╡ 2ffc741b-09c2-4e44-a190-f187a0a7b6cd
#all_lines = readlines(fname)

# ╔═╡ f56b519f-df0f-442d-835a-e4c8aa94af1f
md"""
### Parse to DataFrame
"""

# ╔═╡ 5d72dcbb-c814-4ed5-b9dd-0ba3cdf27b9d
function log_to_df(fname, filter_string, dict_field)

	all_dict = []

	open(fname, "r") do file
		for line in eachline(file)
			try
				line_dict = JSON.parse(line)
				if occursin(filter_string, line_dict[dict_field])
		            push!(all_dict, line_dict)
				end
		    catch
			    continue
			end
		end		
	end

	# Nested dicts cause problems when converting to a DataFrame
	for each_dict in all_dict
		if haskey(each_dict, "exception")
			delete!(each_dict, "exception")
		end
	end

	df = DataFrame[]

	if ~isempty(all_dict)
		df = DataFrame(vcat(all_dict...))

		# Parse the timestamp column into DateTime objects
		df.time = DateTime.(df.time, "yyyy-mm-ddTHH:MM:SS+00:00")
	end
	
	return df

end

# ╔═╡ 0bd70285-6df7-467b-ac34-942d553679dd
md"""
### Check for failed logins
"""

# ╔═╡ 69290ffd-6841-46f0-b927-6314406e5758
#df_log_failed = log_to_df(fname_1, "Login failed", "message")

# ╔═╡ f3a15dca-a3be-4a43-976d-e1894ee7e19d
# # Find the minimum and maximum dates
# (
#     minimum(df_log_failed.time),
#     maximum(df_log_failed.time)
# )

# ╔═╡ 91015ec6-05ce-4451-b546-a7da73643dc7
md"""
#### Filter based on user id
"""

# ╔═╡ 137080b5-3c45-4a66-8812-ba52b64bb777
# df_failed = filter(row -> ~(occursin("vnegi10", row.message) | 
#                             occursin("mdash", row.message)),
# 	                          df_log_failed)

# ╔═╡ 3e15aa11-084e-404d-a0c0-4078ef9e5f8b
md"""
### Check for domain
"""

# ╔═╡ 53533056-c888-4e63-8844-24cefdc67007
df_domain = log_to_df(fname_2, "Trusted domain", "message")

# ╔═╡ 71fbc64b-ca35-4129-a182-95a43deae8db
# Find the minimum and maximum dates
(
    minimum(df_domain.time),
    maximum(df_domain.time)
)

# ╔═╡ 42bc870d-8e98-4d09-b5f8-d3b44e0326b1
rows, cols = size(df_domain)

# ╔═╡ 843b32ef-d77f-483c-b4e6-6e9e5ab78290
df_domain.remoteAddr |> unique |> length

# ╔═╡ a64e8d78-ca5e-43e6-bc23-05b074175536
function get_count(df_domain, gby_cols)

	df_counts = combine(groupby(df_domain, 
		                        gby_cols), 
		                        nrow => :count)
	
	return sort(df_counts, :count, rev = true)

end	

# ╔═╡ df53fd12-1e37-4f3e-9af4-2bddbc6dc477
get_count(df_domain, [:remoteAddr])

# ╔═╡ 1d9bbec8-3930-484f-9922-10d3f4ce96c0
get_count(df_domain, [:userAgent])

# ╔═╡ 8e99afc7-aa99-4ce5-9d45-a77492f0c412
begin
	df_count = get_count(df_domain, [:remoteAddr, :userAgent])
	df_count_filter = filter(row -> (occursin("python", 
		                                       row.userAgent)), df_count) 
end

# ╔═╡ f80fa955-fa16-4524-a3ba-57eecbb58108
df_count_filter

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
DataFrames = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
Dates = "ade2ca70-3891-5945-98fb-dc099432e06a"
JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"

[compat]
DataFrames = "~1.7.0"
JSON = "~0.21.4"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.11.1"
manifest_format = "2.0"
project_hash = "3c877d70bba1c26e0fb7d46c581d88e4f74447aa"

[[deps.Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"
version = "1.11.0"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"
version = "1.11.0"

[[deps.Compat]]
deps = ["TOML", "UUIDs"]
git-tree-sha1 = "8ae8d32e09f0dcf42a36b90d4e17f5dd2e4c4215"
uuid = "34da2185-b29b-5c13-b0c7-acf172513d20"
version = "4.16.0"
weakdeps = ["Dates", "LinearAlgebra"]

    [deps.Compat.extensions]
    CompatLinearAlgebraExt = "LinearAlgebra"

[[deps.CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"
version = "1.1.1+0"

[[deps.Crayons]]
git-tree-sha1 = "249fe38abf76d48563e2f4556bebd215aa317e15"
uuid = "a8cc5b0e-0ffa-5ad4-8c14-923d3ee1735f"
version = "4.1.1"

[[deps.DataAPI]]
git-tree-sha1 = "abe83f3a2f1b857aac70ef8b269080af17764bbe"
uuid = "9a962f9c-6df0-11e9-0e5d-c546b8b5ee8a"
version = "1.16.0"

[[deps.DataFrames]]
deps = ["Compat", "DataAPI", "DataStructures", "Future", "InlineStrings", "InvertedIndices", "IteratorInterfaceExtensions", "LinearAlgebra", "Markdown", "Missings", "PooledArrays", "PrecompileTools", "PrettyTables", "Printf", "Random", "Reexport", "SentinelArrays", "SortingAlgorithms", "Statistics", "TableTraits", "Tables", "Unicode"]
git-tree-sha1 = "fb61b4812c49343d7ef0b533ba982c46021938a6"
uuid = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
version = "1.7.0"

[[deps.DataStructures]]
deps = ["Compat", "InteractiveUtils", "OrderedCollections"]
git-tree-sha1 = "1d0a14036acb104d9e89698bd408f63ab58cdc82"
uuid = "864edb3b-99cc-5e75-8d2d-829cb0a9cfe8"
version = "0.18.20"

[[deps.DataValueInterfaces]]
git-tree-sha1 = "bfc1187b79289637fa0ef6d4436ebdfe6905cbd6"
uuid = "e2d170a0-9d28-54be-80f0-106bbe20a464"
version = "1.0.0"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
version = "1.11.0"

[[deps.Future]]
deps = ["Random"]
uuid = "9fa8497b-333b-5362-9e8d-4d0656e87820"
version = "1.11.0"

[[deps.InlineStrings]]
git-tree-sha1 = "45521d31238e87ee9f9732561bfee12d4eebd52d"
uuid = "842dd82b-1e85-43dc-bf29-5d0ee9dffc48"
version = "1.4.2"

    [deps.InlineStrings.extensions]
    ArrowTypesExt = "ArrowTypes"
    ParsersExt = "Parsers"

    [deps.InlineStrings.weakdeps]
    ArrowTypes = "31f734f8-188a-4ce0-8406-c8a06bd891cd"
    Parsers = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"

[[deps.InteractiveUtils]]
deps = ["Markdown"]
uuid = "b77e0a4c-d291-57a0-90e8-8db25a27a240"
version = "1.11.0"

[[deps.InvertedIndices]]
git-tree-sha1 = "0dc7b50b8d436461be01300fd8cd45aa0274b038"
uuid = "41ab1584-1d38-5bbf-9106-f11c6c58b48f"
version = "1.3.0"

[[deps.IteratorInterfaceExtensions]]
git-tree-sha1 = "a3f24677c21f5bbe9d2a714f95dcd58337fb2856"
uuid = "82899510-4779-5014-852e-03e436cf321d"
version = "1.0.0"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers", "Unicode"]
git-tree-sha1 = "31e996f0a15c7b280ba9f76636b3ff9e2ae58c9a"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.LaTeXStrings]]
git-tree-sha1 = "dda21b8cbd6a6c40d9d02a73230f9d70fed6918c"
uuid = "b964fa9f-0449-5b57-a5c2-d3ea65f4040f"
version = "1.4.0"

[[deps.Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"
version = "1.11.0"

[[deps.LinearAlgebra]]
deps = ["Libdl", "OpenBLAS_jll", "libblastrampoline_jll"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
version = "1.11.0"

[[deps.Markdown]]
deps = ["Base64"]
uuid = "d6f4376e-aef5-505a-96c1-9c027394607a"
version = "1.11.0"

[[deps.Missings]]
deps = ["DataAPI"]
git-tree-sha1 = "ec4f7fbeab05d7747bdf98eb74d130a2a2ed298d"
uuid = "e1d29d7a-bbdc-5cf2-9ac0-f12de2c33e28"
version = "1.2.0"

[[deps.Mmap]]
uuid = "a63ad114-7e13-5084-954f-fe012c677804"
version = "1.11.0"

[[deps.OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"
version = "0.3.27+1"

[[deps.OrderedCollections]]
git-tree-sha1 = "dfdf5519f235516220579f949664f1bf44e741c5"
uuid = "bac558e1-5e72-5ebc-8fee-abe8a469f55d"
version = "1.6.3"

[[deps.Parsers]]
deps = ["Dates", "PrecompileTools", "UUIDs"]
git-tree-sha1 = "8489905bcdbcfac64d1daa51ca07c0d8f0283821"
uuid = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"
version = "2.8.1"

[[deps.PooledArrays]]
deps = ["DataAPI", "Future"]
git-tree-sha1 = "36d8b4b899628fb92c2749eb488d884a926614d3"
uuid = "2dfb63ee-cc39-5dd5-95bd-886bf059d720"
version = "1.4.3"

[[deps.PrecompileTools]]
deps = ["Preferences"]
git-tree-sha1 = "5aa36f7049a63a1528fe8f7c3f2113413ffd4e1f"
uuid = "aea7be01-6a6a-4083-8856-8a6e6704d82a"
version = "1.2.1"

[[deps.Preferences]]
deps = ["TOML"]
git-tree-sha1 = "9306f6085165d270f7e3db02af26a400d580f5c6"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.4.3"

[[deps.PrettyTables]]
deps = ["Crayons", "LaTeXStrings", "Markdown", "PrecompileTools", "Printf", "Reexport", "StringManipulation", "Tables"]
git-tree-sha1 = "1101cd475833706e4d0e7b122218257178f48f34"
uuid = "08abe8d2-0d0c-5749-adfa-8a2ac140af0d"
version = "2.4.0"

[[deps.Printf]]
deps = ["Unicode"]
uuid = "de0858da-6303-5e67-8744-51eddeeeb8d7"
version = "1.11.0"

[[deps.Random]]
deps = ["SHA"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"
version = "1.11.0"

[[deps.Reexport]]
git-tree-sha1 = "45e428421666073eab6f2da5c9d310d99bb12f9b"
uuid = "189a3867-3050-52da-a836-e630ba90ab69"
version = "1.2.2"

[[deps.SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"
version = "0.7.0"

[[deps.SentinelArrays]]
deps = ["Dates", "Random"]
git-tree-sha1 = "d0553ce4031a081cc42387a9b9c8441b7d99f32d"
uuid = "91c51154-3ec4-41a3-a24f-3f23e20d615c"
version = "1.4.7"

[[deps.SortingAlgorithms]]
deps = ["DataStructures"]
git-tree-sha1 = "66e0a8e672a0bdfca2c3f5937efb8538b9ddc085"
uuid = "a2af1166-a08f-5f64-846c-94a0d3cef48c"
version = "1.2.1"

[[deps.Statistics]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "ae3bb1eb3bba077cd276bc5cfc337cc65c3075c0"
uuid = "10745b16-79ce-11e8-11f9-7d13ad32a3b2"
version = "1.11.1"

    [deps.Statistics.extensions]
    SparseArraysExt = ["SparseArrays"]

    [deps.Statistics.weakdeps]
    SparseArrays = "2f01184e-e22b-5df5-ae63-d93ebab69eaf"

[[deps.StringManipulation]]
deps = ["PrecompileTools"]
git-tree-sha1 = "a6b1675a536c5ad1a60e5a5153e1fee12eb146e3"
uuid = "892a3eda-7b42-436c-8928-eab12a02cf0e"
version = "0.4.0"

[[deps.TOML]]
deps = ["Dates"]
uuid = "fa267f1f-6049-4f14-aa54-33bafae1ed76"
version = "1.0.3"

[[deps.TableTraits]]
deps = ["IteratorInterfaceExtensions"]
git-tree-sha1 = "c06b2f539df1c6efa794486abfb6ed2022561a39"
uuid = "3783bdb8-4a98-5b6b-af9a-565f29a5fe9c"
version = "1.0.1"

[[deps.Tables]]
deps = ["DataAPI", "DataValueInterfaces", "IteratorInterfaceExtensions", "OrderedCollections", "TableTraits"]
git-tree-sha1 = "598cd7c1f68d1e205689b1c2fe65a9f85846f297"
uuid = "bd369af6-aec1-5ad0-b16a-f7cc5008161c"
version = "1.12.0"

[[deps.UUIDs]]
deps = ["Random", "SHA"]
uuid = "cf7118a7-6976-5b1a-9a39-7adc72f591a4"
version = "1.11.0"

[[deps.Unicode]]
uuid = "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"
version = "1.11.0"

[[deps.libblastrampoline_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850b90-86db-534c-a0d3-1478176c7d93"
version = "5.11.0+0"
"""

# ╔═╡ Cell order:
# ╠═f87b8466-dc05-11ef-2c7f-6585551df9a1
# ╟─4d81e853-e592-40c0-a66a-f5fa11467fe9
# ╠═15e06b0a-13de-4d70-99aa-f870b3b07732
# ╠═2ffc741b-09c2-4e44-a190-f187a0a7b6cd
# ╟─f56b519f-df0f-442d-835a-e4c8aa94af1f
# ╟─5d72dcbb-c814-4ed5-b9dd-0ba3cdf27b9d
# ╟─0bd70285-6df7-467b-ac34-942d553679dd
# ╠═69290ffd-6841-46f0-b927-6314406e5758
# ╠═f3a15dca-a3be-4a43-976d-e1894ee7e19d
# ╟─91015ec6-05ce-4451-b546-a7da73643dc7
# ╠═137080b5-3c45-4a66-8812-ba52b64bb777
# ╟─3e15aa11-084e-404d-a0c0-4078ef9e5f8b
# ╠═53533056-c888-4e63-8844-24cefdc67007
# ╠═71fbc64b-ca35-4129-a182-95a43deae8db
# ╠═42bc870d-8e98-4d09-b5f8-d3b44e0326b1
# ╠═843b32ef-d77f-483c-b4e6-6e9e5ab78290
# ╟─a64e8d78-ca5e-43e6-bc23-05b074175536
# ╠═df53fd12-1e37-4f3e-9af4-2bddbc6dc477
# ╠═1d9bbec8-3930-484f-9922-10d3f4ce96c0
# ╠═8e99afc7-aa99-4ce5-9d45-a77492f0c412
# ╠═f80fa955-fa16-4524-a3ba-57eecbb58108
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
